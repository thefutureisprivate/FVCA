//! Attended boot-slot installation after an authenticated mirror replacement.

use std::fs;
use std::io::{self, Write};
use std::path::Path;

use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::{
    Artifact, BootRoute, Disk, ReleaseEpoch, ReviewedDisk, SLOT, StorageUnlock, WritableSlot,
    check_sector, floor, install_payload, loader, require_distinct_disks, reviewed,
    reviewed_layout,
};
use crate::{MANIFEST_BYTES, Result, Role, install, invalid, state, valid_digest};

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Phase {
    PrepareReplacement,
    CompletePair,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Release {
    epoch: u64,
    manifest_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Slot {
    disk: ReviewedDisk,
    release: Release,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Approval {
    schema: String,
    phase: Phase,
    valid_from: i64,
    expires: i64,
    sector_size: u64,
    secure_boot_certificate_sha256: String,
    epoch_policy_sha256: String,
    floor: u64,
    unlock: StorageUnlock,
    storage_pcr_key_fingerprint: String,
    previous_storage_policy_sha256: String,
    repaired_storage_policy_sha256: String,
    mirror_repair_evidence_sha256: String,
    replacement_boot_evidence_sha256: Option<String>,
    previous_survivor: Release,
    survivor: Slot,
    replacement: Slot,
}

fn evidence(value: &str) -> bool {
    valid_digest(value) && value.bytes().any(|byte| byte != b'0')
}

impl Approval {
    fn validate(&self) -> Result<()> {
        check_sector(self.sector_size)?;
        if self.schema != "fvca-hypervisor-repaired-slot-v1"
            || self.valid_from <= 0
            || !matches!(self.expires.checked_sub(self.valid_from), Some(1..=86400))
        {
            return Err(
                invalid("invalid repaired slot approval schema or validity interval").into(),
            );
        }
        let proposed = [&self.survivor.release, &self.replacement.release];
        let manifests = [
            self.previous_survivor.manifest_sha256.as_str(),
            &proposed[0].manifest_sha256,
            &proposed[1].manifest_sha256,
        ];
        if self.floor == 0
            || self.previous_survivor.epoch < self.floor
            || proposed
                .iter()
                .any(|release| release.epoch < self.previous_survivor.epoch)
            || manifests[0] == manifests[1]
            || manifests[0] == manifests[2]
            || manifests[1] == manifests[2]
        {
            return Err(invalid("repaired slots require distinct approved releases at or above the previous epoch and live floor").into());
        }
        if self.previous_storage_policy_sha256 == self.repaired_storage_policy_sha256
            || self.survivor.disk.gpt_sha256 == self.replacement.disk.gpt_sha256
            || [&self.survivor, &self.replacement]
                .iter()
                .any(|slot| !slot.disk.path.is_absolute())
            || [
                &self.secure_boot_certificate_sha256,
                &self.epoch_policy_sha256,
                &self.storage_pcr_key_fingerprint,
                &self.previous_storage_policy_sha256,
                &self.repaired_storage_policy_sha256,
                &self.mirror_repair_evidence_sha256,
                &self.survivor.disk.gpt_sha256,
                &self.replacement.disk.gpt_sha256,
            ]
            .into_iter()
            .map(String::as_str)
            .chain(manifests)
            .any(|value| !evidence(value))
        {
            return Err(invalid("repaired slot approval must pin distinct reviewed disks, storage policies and repair evidence").into());
        }
        match (self.phase, self.replacement_boot_evidence_sha256.as_deref()) {
            (Phase::PrepareReplacement, None) => Ok(()),
            (Phase::CompletePair, Some(digest))
                if evidence(digest) && digest != self.mirror_repair_evidence_sha256 =>
            {
                Ok(())
            }
            _ => Err(invalid(
                "completing the repaired pair requires separate replacement boot evidence",
            )
            .into()),
        }
    }

    fn authorize(&self) -> Result<()> {
        let now = jiff::Timestamp::now().as_second();
        if !(self.valid_from..self.expires).contains(&now) {
            return Err(invalid("repaired slot approval is outside its validity interval").into());
        }
        if floor::read_current(&self.epoch_policy_sha256)? != self.floor {
            return Err(invalid("live TPM floor differs from the repaired slot approval").into());
        }
        Ok(())
    }

    fn epoch(&self, release: &Release, previous: bool) -> ReleaseEpoch<'_> {
        ReleaseEpoch {
            number: release.epoch,
            policy: &self.epoch_policy_sha256,
            storage_pcr: Some((&self.storage_pcr_key_fingerprint, self.unlock)),
            storage_policy: Some(if previous {
                &self.previous_storage_policy_sha256
            } else {
                &self.repaired_storage_policy_sha256
            }),
            boot: if previous {
                BootRoute::Either
            } else {
                BootRoute::Ordinary
            },
            trial: None,
            trial_key: None,
        }
    }

    fn staged(&self, state: &Path, release: &Release) -> Result<Artifact> {
        let directory = state.join("staged").join(&release.manifest_sha256);
        install::verify(
            &directory,
            Role::Hypervisor,
            release.epoch,
            &release.manifest_sha256,
        )?;
        Artifact::open(&directory, self.sector_size)
    }
}

pub fn install_repaired(
    state_dir: &Path,
    approval_path: &Path,
    signature_path: &Path,
    authority_path: &Path,
    certificate_path: &Path,
) -> Result<()> {
    let raw = state::read(approval_path, MANIFEST_BYTES)?;
    let signature = state::read(signature_path, 64)?;
    let key = state::read(authority_path, 32)?;
    UnparsedPublicKey::new(&ED25519, &key)
        .verify(&raw, &signature)
        .map_err(|_| invalid("independent repaired slot approval signature is invalid"))?;
    let approval: Approval = serde_json::from_slice(&raw)?;
    approval.validate()?;
    let certificate = state::read(certificate_path, MANIFEST_BYTES)?;
    if hex::encode(Sha256::digest(&certificate)) != approval.secure_boot_certificate_sha256 {
        return Err(
            invalid("Secure Boot certificate differs from the repaired slot approval").into(),
        );
    }
    let _state_lease = state::lock(state_dir)?;
    // Only a crashed operation can leave this directory behind while the
    // intake lock is free. Reclaim it before starting another installation.
    const SCRATCH: &str = ".repaired-install";
    match fs::remove_dir_all(state_dir.join(SCRATCH)) {
        Ok(()) => (),
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    let scratch = tempfile::Builder::new()
        .prefix(SCRATCH)
        .rand_bytes(0)
        .tempdir_in(state_dir)?;
    let certificate_path = scratch.path().join("secure-boot.pem");
    fs::write(&certificate_path, &certificate)?;
    let cert = state::open_regular(&certificate_path)?;

    let preparing = matches!(approval.phase, Phase::PrepareReplacement);
    let (protected, target) = if preparing {
        (&approval.survivor, &approval.replacement)
    } else {
        (&approval.replacement, &approval.survivor)
    };
    let sector = approval.sector_size;
    let (protected_disk, protected_layout) = reviewed(&protected.disk, sector)?;
    let (target_disk, target_layout) = reviewed_layout(
        &target.disk,
        sector,
        Disk::update_target(&target.disk.path, sector)?,
    )?;
    require_distinct_disks(
        (&protected_disk, &protected_layout),
        (&target_disk, &target_layout),
    )?;
    if !target_disk.physical && !cfg!(feature = "swtpm-test") {
        return Err(invalid(
            "repaired slot installation requires two reviewed, unused NVMe namespaces",
        )
        .into());
    }
    approval.authorize()?;

    let previous_epoch = approval.epoch(&approval.previous_survivor, true);
    let previous = approval.staged(state_dir, &approval.previous_survivor)?;
    let previous_loader = if preparing {
        previous.verify_installed(
            &protected_disk,
            &protected_layout,
            &cert,
            scratch.path(),
            &previous_epoch,
        )?
    } else {
        previous.fits(&target_layout)?;
        loader(
            &previous.file,
            previous.layout.regions[0].extent,
            &cert,
            scratch.path(),
            &previous_epoch,
        )?
    };
    let layouts = if preparing {
        [&protected_layout, &target_layout]
    } else {
        [&target_layout, &protected_layout]
    };
    let original = &previous_loader.host_storage.partitions;
    if !original.contains(&layouts[0].regions[SLOT.len()].uuid)
        || original.contains(&layouts[1].regions[SLOT.len()].uuid)
    {
        return Err(invalid(
            "repaired storage must retain the survivor and substitute exactly the failed partition",
        )
        .into());
    }

    let protected_release = approval.staged(state_dir, &protected.release)?;
    let protected_epoch = approval.epoch(&protected.release, false);
    let protected_loader = if preparing {
        protected_release.fits(&protected_layout)?;
        loader(
            &protected_release.file,
            protected_release.layout.regions[0].extent,
            &cert,
            scratch.path(),
            &protected_epoch,
        )?
    } else {
        // Keep the already boot-tested replacement available while rebuilding
        // the survivor, including on retries after its ESP has been cleared.
        protected_release.verify_installed(
            &protected_disk,
            &protected_layout,
            &cert,
            scratch.path(),
            &protected_epoch,
        )?
    };
    let candidate = approval.staged(state_dir, &target.release)?;
    candidate.fits(&target_layout)?;
    let candidate_loader = loader(
        &candidate.file,
        candidate.layout.regions[0].extent,
        &cert,
        scratch.path(),
        &approval.epoch(&target.release, false),
    )?;
    protected_loader.require_storage_pair(&candidate_loader, layouts)?;
    previous_loader.require_host_configuration(&protected_loader, false, None)?;
    previous_loader.require_host_configuration(&candidate_loader, false, None)?;
    // The repair writer claims the data member separately, read-only, to
    // ensure no live mapping can use this disk during offline provisioning.
    let _data = target_disk
        .physical
        .then(|| {
            target_disk.claim_partitions(
                target_layout
                    .regions
                    .last_chunk::<1>()
                    .expect("data region"),
                false,
            )
        })
        .transpose()?;
    let writable = WritableSlot::claim(&target_disk, &target_layout)?;
    let mut output = io::stdout().lock();
    install_payload(
        &writable,
        &candidate,
        sector,
        &target.disk.gpt_sha256,
        || approval.authorize(),
        &mut output,
    )?;
    let stage = if preparing {
        "prepare-replacement"
    } else {
        "complete-pair"
    };
    writeln!(
        output,
        "FVCA_HYPERVISOR_REPAIRED_SLOT_INSTALLED {stage} {} {} {}",
        target_layout.id,
        target.release.manifest_sha256,
        hex::encode(Sha256::digest(&raw))
    )?;
    Ok(())
}
