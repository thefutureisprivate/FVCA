//! One-time counter enrollment from trusted maintenance media.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, Instant};

use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{
    MAX_APPROVAL_SECONDS, MAX_SESSION_SECONDS, check_record, read_signature, record, reference,
    tpm::{Counter, Tpm},
};
use crate::{MANIFEST_BYTES, Result, invalid, state};

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Target {
    ak_qualified_name: String,
    epoch_policy_sha256: String,
    increment_key_sha256: String,
    policy_reference_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Approval {
    schema: String,
    valid_from: i64,
    expires: i64,
    target: Target,
}

impl Approval {
    fn remaining(&self) -> Result<u32> {
        let now = jiff::Timestamp::now().as_second();
        if !(self.valid_from..self.expires).contains(&now) {
            return Err(invalid("initial floor approval is outside its validity interval").into());
        }
        Ok((self.expires - now).min(MAX_SESSION_SECONDS).try_into()?)
    }
}

fn digest(input: &[u8]) -> String {
    hex::encode(Sha256::digest(input))
}

fn prepare(key_path: &Path, reference_path: &Path) -> Result<(Tpm, Target, [u8; 40])> {
    let key = state::read(key_path, 1024)?;
    let reference = reference(reference_path)?;
    let (tpm, policy, identity) = Tpm::prepare(&key, &reference)?;
    Ok((
        tpm,
        Target {
            ak_qualified_name: hex::encode(identity),
            epoch_policy_sha256: hex::encode(policy),
            increment_key_sha256: digest(&key),
            policy_reference_sha256: digest(&reference),
        },
        reference,
    ))
}

fn owner_authorization(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let mut file = state::open_regular(path)?;
    let info = file.metadata()?;
    if info.uid() != rustix::process::geteuid().as_raw()
        || !matches!(info.mode() & 0o7777, 0o400 | 0o600)
        || info.nlink() != 1
        || info.len() != 32
    {
        return Err(invalid("expected a private 32-byte owner authorization file").into());
    }
    let mut secret = Zeroizing::new([0; 32]);
    file.read_exact(secret.as_mut())?;
    if *secret == [0; 32] || file.read(&mut [0; 1])? != 0 {
        return Err(invalid("invalid owner authorization file contents").into());
    }
    Ok(secret)
}

pub fn inspect_floor_enrollment(key: &Path, reference: &Path) -> Result<()> {
    let (mut tpm, target, _) = prepare(key, reference)?;
    let counter = match tpm.probe()? {
        Counter::Absent => "absent",
        Counter::Uninitialized => "uninitialized",
        Counter::Initialized => "initialized",
    };
    println!(
        "{}",
        serde_json::json!({
            "schema": "fvca-hypervisor-floor-enrollment-observation-v1",
            "counter": counter,
            "target": target,
        })
    );
    Ok(())
}

pub fn enroll_floor(
    state_dir: &Path,
    approval_path: &Path,
    signature_path: &Path,
    authority_path: &Path,
    [key, reference, owner]: [&Path; 3],
) -> Result<()> {
    let raw = state::read(approval_path, MANIFEST_BYTES)?;
    let signature = state::read(signature_path, 64)?;
    let authority = state::read(authority_path, 32)?;
    UnparsedPublicKey::new(&ED25519, &authority)
        .verify(&raw, &signature)
        .map_err(|_| invalid("initial floor approval signature is invalid"))?;
    let approval: Approval = serde_json::from_slice(&raw)?;
    if approval.schema != "fvca-hypervisor-floor-enrollment-v1"
        || approval.valid_from <= 0
        || !matches!(
            approval.expires.checked_sub(approval.valid_from),
            Some(1..=MAX_APPROVAL_SECONDS)
        )
    {
        return Err(invalid("initial floor approval schema or interval is invalid").into());
    }

    let _lease = state::lock(state_dir)?;
    let (mut tpm, target, reference) = prepare(key, reference)?;
    if target != approval.target {
        return Err(invalid(
            "live TPM identity or proposed counter policy differs from the approval",
        )
        .into());
    }
    let counter = tpm.probe()?;
    let binding = serde_json::to_vec(&target)?;
    let enrollment = state_dir.join("floor-enrollment");
    match state::directory(&enrollment) {
        Ok(()) => (),
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    let intent = enrollment.join("intent.json");
    let defined = enrollment.join("defined.json");
    let intended = check_record(&intent, &binding)?;
    let was_defined = check_record(&defined, &binding)?;
    match counter {
        Counter::Absent if was_defined => {
            return Err(invalid("the previously defined floor counter is missing").into());
        }
        Counter::Uninitialized if !intended => {
            return Err(invalid("existing floor counter has no matching enrollment intent").into());
        }
        Counter::Initialized if !intended || !was_defined => {
            return Err(
                invalid("initialized floor counter has no matching enrollment receipt").into(),
            );
        }
        _ => (),
    }
    if counter != Counter::Initialized {
        approval.remaining()?;
        let credential = if counter == Counter::Absent {
            Some(owner_authorization(owner)?)
        } else {
            None
        };
        state::staged(&enrollment)?;
        File::open(state_dir)?.sync_all()?;
        let approval_digest = digest(&raw);
        let signed = [signature, raw].concat();
        record(
            &enrollment,
            &enrollment.join(format!("approval-{approval_digest}.signed")),
            &signed,
        )?;
        record(&enrollment, &intent, &binding)?;
        if let Some(credential) = credential {
            approval.remaining()?;
            tpm.define(&credential)?;
            if tpm.probe()? != Counter::Uninitialized {
                return Err(invalid("new floor counter has unexpected public state").into());
            }
        }
        record(&enrollment, &defined, &binding)?;
        let seconds = approval.remaining()?;
        let deadline = Instant::now() + Duration::from_secs(u64::from(seconds));
        let message = tpm.initial_challenge(&reference, seconds)?;
        println!(
            "FVCA_HYPERVISOR_FLOOR_ENROLLMENT_CHALLENGE {}",
            serde_json::json!({
                "schema": "fvca-hypervisor-floor-enrollment-challenge-v1",
                "approval_sha256": approval_digest,
                "target": target,
                "message": hex::encode(message),
            })
        );
        io::stdout().flush()?;
        let signature = read_signature(deadline)?;
        tpm.authorize(seconds, &signature)?;
        approval.remaining()?;
        tpm.increment()?;
    }
    drop(tpm);
    // Read through the normal verifier. The NV Name changes on the initial
    // increment when the TPM sets WRITTEN, so use a new ESAPI context.
    let mut policy = [0; 32];
    hex::decode_to_slice(&target.epoch_policy_sha256, &mut policy)?;
    let epoch = Tpm::open(&policy)?.read()?;
    if epoch == 0 {
        return Err(invalid("initial TPM floor is zero").into());
    }
    let policy_conf = format!(
        "FVCA-HYPERVISOR-EPOCH-1\nepoch={epoch}\npolicy_sha256={}\n",
        target.epoch_policy_sha256,
    );
    let path = enrollment.join("epoch.conf");
    record(&enrollment, &path, policy_conf.as_bytes())?;
    println!(
        "FVCA_HYPERVISOR_FLOOR_ENROLLED {epoch} {}",
        target.epoch_policy_sha256
    );
    Ok(())
}
