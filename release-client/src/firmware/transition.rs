//! Verify the boot and storage policies qualified for this exact firmware transition.

use std::fs::File;
use std::io;

use serde::{Deserialize, Serialize};
use tough::Repository;

use super::{DeviceIdentity, Head, Offer, Version, boot, boot_id};
use crate::{
    Result,
    channel::{digest, target},
    invalid,
};

pub(super) const FILE: &str = "transition.json";
pub(super) const LIMIT: u64 = 8192;
const SCHEMA: &str = "fvca-firmware-boot-transition-v3";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct QualificationAge {
    qualified_at: i64,
    observed_at: i64,
    age_seconds: u64,
}

impl QualificationAge {
    pub(super) fn at(qualified_at: i64, observed_at: i64) -> io::Result<Self> {
        if qualified_at <= 0 || qualified_at > observed_at {
            return Err(invalid(
                "firmware transition qualification is in the future or has no date",
            ));
        }
        Ok(Self {
            qualified_at,
            observed_at,
            age_seconds: (observed_at - qualified_at) as u64,
        })
    }
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(super) enum KeyRelease {
    PreserveEnrollment,
    RequiresPreparation,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Transition {
    schema: String,
    system_uuid: String,
    fwupd_version: String,
    device: DeviceIdentity,
    from: Version,
    to: Version,
    archive_sha256: String,
    payload_sha256: String,
    pub(super) qualified_at: i64,
    pub(super) key_release: KeyRelease,
    pub(super) before: boot::Policy,
    pub(super) after: boot::Policy,
}

impl Transition {
    pub(super) fn parse(body: &[u8], head: &Head, offer: &Offer) -> Result<Self> {
        if body.len() as u64 > LIMIT
            || digest(body) != offer.qualification.transition_evidence_sha256
        {
            return Err(
                invalid("firmware transition evidence differs from the signed offer").into(),
            );
        }
        let record: Self = serde_json::from_slice(body)?;
        if record.schema != SCHEMA
            || record.system_uuid != head.system_uuid
            || record.fwupd_version != head.fwupd_version
            || record.device != offer.device
            || record.from != offer.from
            || record.to != offer.to
            || record.archive_sha256 != offer.archive.sha256
            || record.payload_sha256 != offer.payload_sha256
        {
            return Err(
                invalid("firmware transition evidence differs from the qualified release").into(),
            );
        }
        if !record.before.valid()
            || !record.after.valid()
            || record.before.filesystem != record.after.filesystem
            || record.after.epoch < record.before.epoch
            || record.after.tpm_floor < record.before.tpm_floor
        {
            return Err(invalid(
                "firmware transition evidence has invalid boot or storage policies",
            )
            .into());
        }
        if !(1..head.expires).contains(&record.qualified_at) {
            return Err(invalid("invalid firmware transition qualification date").into());
        }
        if record.key_release == KeyRelease::PreserveEnrollment && record.before != record.after {
            return Err(invalid(
                "firmware transition changes the boot or storage policy under preserved TPM enrollment",
            )
            .into());
        }
        Ok(record)
    }
}

pub(super) async fn download(
    repo: &Repository,
    head: &Head,
    offer: &Offer,
) -> Result<(Vec<u8>, Transition)> {
    let name = format!(
        "fvca-firmware-transition-{}.json",
        offer.qualification.transition_evidence_sha256
    );
    let bytes = target(repo, name, LIMIT).await?;
    let record = Transition::parse(&bytes, head, offer)?;
    Ok((bytes, record))
}

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub(super) enum Status {
    Matched,
    Blocked { reason: String },
}

/// The caller holds the Host lifecycle lease and has checked that it is idle.
pub(super) fn preflight(pool: &File, expected: &boot::Policy) -> Status {
    match boot_id() {
        Ok(id) => compare(expected, &boot::inspect(pool, &id)),
        Err(error) => Status::Blocked {
            reason: error.to_string(),
        },
    }
}

pub(super) fn compare(expected: &boot::Policy, observed: &boot::Evidence) -> Status {
    let reason = match observed {
        boot::Evidence::Observed(boot) if &boot.policy != expected => {
            "current boot differs from the exact qualified boot and storage policy"
        }
        boot::Evidence::Observed(boot) if !boot.storage_error_free => {
            "Btrfs mirror members report persistent errors"
        }
        boot::Evidence::Observed(_) => return Status::Matched,
        boot::Evidence::Unavailable { reason } => reason,
    };
    Status::Blocked {
        reason: reason.into(),
    }
}
