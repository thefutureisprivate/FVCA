//! Independent authorization and readback of an installed Hypervisor boot pair.

mod tpm;

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::{
    Artifact, Disk, Layout, ReleaseEpoch, ReviewedDisk, check_sector, require_distinct_disks, reviewed,
};
use crate::{MANIFEST_BYTES, Result, Role, install, invalid, state, valid_digest};

const MAX_APPROVAL_SECONDS: i64 = 24 * 60 * 60;
const MAX_SESSION_SECONDS: i64 = 300;
const POLICY_REFERENCE_PREFIX: &[u8; 24] = b"FVCA-HYPERVISOR-FLOOR-1\0";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovedSlot {
    disk: ReviewedDisk,
    epoch: u64,
    manifest_sha256: String,
    boot_evidence_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Approval {
    schema: String,
    valid_from: i64,
    expires: i64,
    sector_size: u64,
    secure_boot_certificate_sha256: String,
    epoch_policy_sha256: String,
    previous_floor: u64,
    next_floor: u64,
    primary: ApprovedSlot,
    recovery: ApprovedSlot,
}

fn nonzero_digest(value: &str) -> bool {
    valid_digest(value) && value.bytes().any(|byte| byte != b'0')
}

impl Approval {
    fn validate(&self) -> Result<()> {
        check_sector(self.sector_size)?;
        if self.schema != "fvca-hypervisor-floor-approval-v1"
            || self.valid_from <= 0
            || self.expires <= self.valid_from
            || self.expires - self.valid_from > MAX_APPROVAL_SECONDS
        {
            return Err(invalid(
                "Hypervisor floor approval schema or validity interval is invalid",
            )
            .into());
        }
        if self.previous_floor == 0
            || self.previous_floor.checked_add(1) != Some(self.next_floor)
            || !nonzero_digest(&self.epoch_policy_sha256)
            || !nonzero_digest(&self.secure_boot_certificate_sha256)
        {
            return Err(invalid("floor approval requires one TPM counter step and the reviewed signing and enrollment digests").into());
        }
        for slot in [&self.primary, &self.recovery] {
            if slot.epoch < self.next_floor
                || !slot.disk.path.is_absolute()
                || !nonzero_digest(&slot.disk.gpt_sha256)
                || !nonzero_digest(&slot.manifest_sha256)
                || !nonzero_digest(&slot.boot_evidence_sha256)
            {
                return Err(invalid(
                    "both reviewed boot paths must meet the next floor and carry boot evidence",
                )
                .into());
            }
        }
        if self.primary.disk.gpt_sha256 == self.recovery.disk.gpt_sha256
            || self.primary.manifest_sha256 == self.recovery.manifest_sha256
            || self.primary.boot_evidence_sha256 == self.recovery.boot_evidence_sha256
        {
            return Err(invalid(
                "floor approval requires independent primary and recovery boot paths",
            )
            .into());
        }
        Ok(())
    }

    fn remaining(&self) -> Result<u32> {
        let now = jiff::Timestamp::now().as_second();
        if !(self.valid_from..self.expires).contains(&now) {
            return Err(invalid(
                "Hypervisor floor approval schema or validity interval is invalid",
            )
            .into());
        }
        Ok((self.expires - now).min(MAX_SESSION_SECONDS).try_into()?)
    }
}

fn read_signature(deadline: Instant) -> Result<[u8; 64]> {
    let input = io::stdin();
    let mut wire = [0u8; 129];
    let mut received = 0;
    while received < wire.len() {
        let left = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| invalid("TPM challenge expired while waiting for its signature"))?;
        let mut fds = [PollFd::new(&input, PollFlags::IN)];
        match poll(&mut fds, Some(&Timespec::try_from(left)?)) {
            Ok(0) => {
                return Err(
                    invalid("TPM challenge expired while waiting for its signature").into(),
                );
            }
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
            Ok(_) => (),
        }
        let count = rustix::io::read(&input, &mut wire[received..])?;
        if count == 0 {
            return Err(invalid("missing TPM session signature").into());
        }
        received += count;
    }
    if wire[128] != b'\n' {
        return Err(invalid(
            "expected a 128-character TPM session signature followed by a newline",
        )
        .into());
    }
    let mut signature = [0u8; 64];
    hex::decode_to_slice(&wire[..128], &mut signature)?;
    Ok(signature)
}

fn check_record(path: &Path, expected: &[u8]) -> Result<bool> {
    match state::read(path, expected.len().try_into()?) {
        Ok(bytes) if bytes == expected => Ok(true),
        Ok(_) => Err(invalid(
            "existing floor transaction record differs from the verified approval",
        )
        .into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn record(directory: &Path, path: &Path, data: &[u8]) -> Result<()> {
    if !check_record(path, data)? {
        let mut scratch = tempfile::NamedTempFile::new_in(directory)?;
        scratch.write_all(data)?;
        scratch.as_file().sync_all()?;
        scratch.persist_noclobber(path)?;
    }
    File::open(directory)?.sync_all()?;
    Ok(())
}

fn advance(
    approved: &Approval,
    state_dir: &Path,
    signed_approval: &[u8],
    approval_digest: &str,
    increment_authority: &Path,
    policy_reference: &Path,
) -> Result<()> {
    let mut policy = [0u8; 32];
    hex::decode_to_slice(&approved.epoch_policy_sha256, &mut policy)?;
    let mut tpm = tpm::Tpm::open(&policy)?;
    let current = tpm.read()?;
    if current != approved.previous_floor && current != approved.next_floor {
        return Err(invalid("live TPM floor is outside the approved transition").into());
    }
    let transactions = state_dir.join("floor-transactions");
    state::staged(&transactions)?;
    File::open(state_dir)?.sync_all()?;
    let intent = transactions.join(format!("{approval_digest}.intent"));
    let committed = transactions.join(format!("{approval_digest}.committed"));
    let receipt = format!(
        "FVCA_HYPERVISOR_FLOOR_COMMITTED {} {approval_digest}\n",
        approved.next_floor
    );
    if check_record(&committed, receipt.as_bytes())? && current != approved.next_floor {
        return Err(invalid("durable commit record is ahead of the live TPM floor").into());
    }
    if current == approved.next_floor {
        if !check_record(&intent, signed_approval)? {
            return Err(invalid(
                "the TPM is already at the target floor without a matching durable intent",
            )
            .into());
        }
    } else {
        let key = state::read(increment_authority, 1024)?;
        let reference: [u8; 40] = state::read(policy_reference, 40)?
            .try_into()
            .map_err(|_| invalid("expected the 40-byte enrolled TPM policy reference"))?;
        if !reference.starts_with(POLICY_REFERENCE_PREFIX) || reference[24..] == [0; 16] {
            return Err(invalid("invalid enrolled TPM policy reference").into());
        }
        let seconds = approved.remaining()?;
        let deadline = Instant::now() + Duration::from_secs(u64::from(seconds));
        let message = tpm.challenge(&key, &reference, seconds)?;
        println!(
            "FVCA_HYPERVISOR_FLOOR_CHALLENGE {}",
            serde_json::json!({
                "schema": "fvca-hypervisor-floor-challenge-v1",
                "approval_sha256": approval_digest,
                "previous_floor": approved.previous_floor,
                "next_floor": approved.next_floor,
                "message": hex::encode(message),
            })
        );
        io::stdout().flush()?;
        let signature = read_signature(deadline)?;
        tpm.authorize(seconds, &signature)?;
        record(&transactions, &intent, signed_approval)?;
        approved.remaining()?;
        if tpm.read()? != approved.previous_floor {
            return Err(invalid("live TPM floor changed during authorization").into());
        }
        let command = tpm.increment();
        let observed = tpm.read().map_err(|error| {
            io::Error::other(format!(
                "TPM floor outcome needs readback after restart: {error}"
            ))
        })?;
        if observed != approved.next_floor {
            command?;
            return Err(invalid("TPM floor differs from the approved readback").into());
        }
    }
    record(&transactions, &committed, receipt.as_bytes())?;
    print!("{receipt}");
    Ok(())
}

pub fn verify_floor(
    state_dir: &Path,
    approval_file: &Path,
    signature_file: &Path,
    authority_file: &Path,
    secure_boot_certificate: &Path,
    increment: Option<(&Path, &Path)>,
) -> Result<()> {
    let raw = state::read(approval_file, MANIFEST_BYTES)?;
    let signature = state::read(signature_file, 64)?;
    let key = state::read(authority_file, 32)?;
    UnparsedPublicKey::new(&ED25519, &key)
        .verify(&raw, &signature)
        .map_err(|_| invalid("independent Hypervisor floor approval signature is invalid"))?;
    let approved: Approval = serde_json::from_slice(&raw)?;
    approved.validate()?;
    if increment.is_none() {
        approved.remaining()?;
    }

    let _state_lease = state::lock(state_dir)?;
    let certificate = state::read(secure_boot_certificate, MANIFEST_BYTES)?;
    if hex::encode(Sha256::digest(&certificate)) != approved.secure_boot_certificate_sha256 {
        return Err(
            invalid("Secure Boot certificate differs from the independent floor approval").into(),
        );
    }
    let scratch = tempfile::Builder::new()
        .prefix(".floor-")
        .tempdir_in(state_dir)?;
    let cert_path = scratch.path().join("secure-boot.pem");
    fs::write(&cert_path, &certificate)?;
    let cert = state::open_regular(&cert_path)?;
    let primary = reviewed(&approved.primary.disk, approved.sector_size)?;
    let recovery = reviewed(&approved.recovery.disk, approved.sector_size)?;
    require_distinct_disks((&primary.0, &primary.1), (&recovery.0, &recovery.1))?;
    if increment.is_some() && !cfg!(feature = "swtpm-test") && !primary.0.physical {
        return Err(
            invalid("TPM floor advancement requires the two reviewed NVMe namespaces").into(),
        );
    }
    let verify = |slot: &ApprovedSlot, (disk, layout): &(Disk, Layout<8>)| {
        let staged = state_dir.join("staged").join(&slot.manifest_sha256);
        install::verify(&staged, Role::Hypervisor, slot.epoch, &slot.manifest_sha256)?;
        Artifact::open(&staged, approved.sector_size)?.verify_installed(
            disk,
            layout,
            &cert,
            scratch.path(),
            &ReleaseEpoch {
                number: slot.epoch,
                policy: &approved.epoch_policy_sha256,
                auto_pcr_key: None,
                storage_policy: None,
                require_trial: false,
                trial: None,
                trial_key: None,
            },
        )
    };
    let stable_loader = verify(&approved.primary, &primary)?;
    let recovery_loader = verify(&approved.recovery, &recovery)?;
    stable_loader.require_storage_pair(&recovery_loader, [&primary.1, &recovery.1])?;
    let approval_digest = hex::encode(Sha256::digest(&raw));
    // Both disk leases and the state lease remain live through the TPM readback.
    if let Some((increment_authority, policy_reference)) = increment {
        let mut record = signature;
        record.extend(raw);
        return advance(
            &approved,
            state_dir,
            &record,
            &approval_digest,
            increment_authority,
            policy_reference,
        );
    }
    approved.remaining()?;
    println!(
        "FVCA_HYPERVISOR_FLOOR_APPROVAL_VERIFIED {} {} {}",
        approved.previous_floor, approved.next_floor, approval_digest,
    );
    Ok(())
}

pub(super) fn read_current(policy: &str) -> Result<u64> {
    let mut index_policy = [0; 32];
    hex::decode_to_slice(policy, &mut index_policy)?;
    Ok(tpm::Tpm::open(&index_policy)?.read()?)
}
