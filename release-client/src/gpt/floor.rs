//! Independent authorization and readback of an installed Hypervisor boot pair.

use std::fs;
use std::path::Path;

use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::{Artifact, ReleaseEpoch, ReviewedDisk, check_sector, require_distinct_disks, reviewed};
use crate::{MANIFEST_BYTES, Result, Role, install, invalid, state, valid_digest};

const MAX_APPROVAL_SECONDS: i64 = 24 * 60 * 60;

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
    fn validate(&self, now: i64) -> Result<()> {
        check_sector(self.sector_size)?;
        if self.schema != "fvca-hypervisor-floor-approval-v1"
            || self.valid_from <= 0
            || !(self.valid_from..self.expires).contains(&now)
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
}

pub fn verify_floor(
    state_dir: &Path,
    approval_file: &Path,
    signature_file: &Path,
    authority_file: &Path,
    secure_boot_certificate: &Path,
) -> Result<()> {
    let raw = state::read(approval_file, MANIFEST_BYTES)?;
    let signature = state::read(signature_file, 64)?;
    let key = state::read(authority_file, 32)?;
    UnparsedPublicKey::new(&ED25519, &key)
        .verify(&raw, &signature)
        .map_err(|_| invalid("independent Hypervisor floor approval signature is invalid"))?;
    let approved: Approval = serde_json::from_slice(&raw)?;
    approved.validate(jiff::Timestamp::now().as_second())?;

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
    let primary = reviewed(&approved.primary.disk, approved.sector_size, false)?;
    let recovery = reviewed(&approved.recovery.disk, approved.sector_size, false)?;
    require_distinct_disks((&primary.0, &primary.1), (&recovery.0, &recovery.1))?;
    for (slot, (disk, layout)) in [
        (&approved.primary, &primary),
        (&approved.recovery, &recovery),
    ] {
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
            },
        )?;
    }
    // Both leases are held until the final expiry check and receipt.
    approved.validate(jiff::Timestamp::now().as_second())?;
    println!(
        "FVCA_HYPERVISOR_FLOOR_APPROVAL_VERIFIED {} {} {}",
        approved.previous_floor,
        approved.next_floor,
        hex::encode(Sha256::digest(&raw))
    );
    Ok(())
}
