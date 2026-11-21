//! Project the updater's durable records without reading staged image data.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use rustix::fs::OFlags;
use serde::{Serialize, de::DeserializeOwned};

use super::{
    ACTIVE_RELEASE, Activation, Active, Checkpoint, Disposition, POLICY_CHECKPOINT, STATUS_SCHEMA,
    Status, UPDATE_STATUS, channel_stem, valid_channel,
};
use crate::{Result, Role, handoff, install::Slot, invalid, valid_digest, valid_uuid};

const RECORD_BYTES: u64 = 4096;

fn directory(role: Role) -> Result<Option<File>> {
    match handoff::require_pool_directory(
        &Path::new("/run/fvca/host-data").join(role.update_state()),
    ) {
        Ok(directory) => Ok(Some(directory)),
        Err(error)
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|error| error.kind() == io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn record<T: DeserializeOwned>(directory: &File, name: &str) -> Result<Option<T>> {
    let flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY;
    let file = match handoff::open_child(directory, name, flags) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    handoff::private_file(&file)?;
    let mut bytes = Vec::new();
    file.take(RECORD_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > RECORD_BYTES {
        return Err(invalid("OS update observation exceeds its bound").into());
    }
    Ok(Some(serde_json::from_slice(&bytes)?))
}

fn validate_active(role: Role, active: &Active) -> Result<()> {
    if active.role != role
        || active.epoch == 0
        || active.sequence == 0
        || !valid_digest(&active.manifest_sha256)
        || match role {
            Role::Hypervisor => active.slot.is_none() || active.guest_bundle.is_some(),
            Role::ServiceGuest => {
                active.slot.is_some() || !active.guest_bundle.as_deref().is_some_and(valid_digest)
            }
        }
    {
        return Err(invalid("invalid recorded active OS release").into());
    }
    Ok(())
}

#[derive(Serialize)]
pub(crate) struct ObservedRelease {
    epoch: u64,
    sequence: u64,
    manifest_sha256: String,
}

pub(crate) fn observed_host_release() -> Result<Option<ObservedRelease>> {
    let Some(directory) = directory(Role::Hypervisor)? else {
        return Ok(None);
    };
    let Some(active) = record::<Active>(&directory, ACTIVE_RELEASE)? else {
        return Ok(None);
    };
    validate_active(Role::Hypervisor, &active)?;
    Ok(Some(ObservedRelease {
        epoch: active.epoch,
        sequence: active.sequence,
        manifest_sha256: active.manifest_sha256,
    }))
}

#[derive(Serialize)]
pub(crate) struct UpdateObservation {
    schema: &'static str,
    role: Role,
    enrolled: bool,
    observed_at: i64,
    recorded_active: Option<Active>,
    last_check: Option<Check>,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Freshness {
    Fresh,
    Expired,
    ClockRegressed,
    Superseded,
    NotApplicable,
}

#[derive(Serialize)]
struct CandidateView {
    epoch: u64,
    manifest_sha256: String,
    #[serde(flatten)]
    activation: Activation,
}

#[derive(Serialize)]
struct Check {
    channel: String,
    policy_revision: u64,
    disposition: Disposition,
    freshness: Freshness,
    last_refresh: Option<i64>,
    fresh_until: Option<i64>,
    channel_sequence: Option<u64>,
    candidate: Option<CandidateView>,
    staged: Option<String>,
    prepared_inactive_slot: Option<Slot>,
    delivered_trial: Option<String>,
    requested_trial: Option<String>,
    hold_until: Option<i64>,
    security_deadline_missed: bool,
}

impl UpdateObservation {
    pub(crate) fn read(role: Role, observed_at: i64) -> Result<Self> {
        let enrolled = Path::new("/run/fvca")
            .join(format!("{}-owner", role.update_state()))
            .try_exists()?;
        let mut observation = Self {
            schema: "fvca-os-release-observation-v1",
            role,
            enrolled,
            observed_at,
            recorded_active: None,
            last_check: None,
        };
        if enrolled && let Some(directory) = directory(role)? {
            let status = record::<Status>(&directory, UPDATE_STATUS)?;
            observation.recorded_active = record(&directory, ACTIVE_RELEASE)?;
            if let Some(active) = &observation.recorded_active {
                validate_active(role, active)?;
            }
            if let Some(status) = status {
                let head = status.validate(role)?;
                let policy_matches = record(&directory, POLICY_CHECKPOINT)?.as_ref()
                    == Some(&status.policy_checkpoint);
                let head_matches = if let Some(head) = head {
                    let stem = channel_stem(role, &status.channel);
                    record(&directory, &format!("{stem}-checkpoint.json"))?.as_ref() == Some(&head)
                } else {
                    true
                };
                let current = policy_matches
                    && head_matches
                    && observation.recorded_active.as_ref() == Some(&status.active);
                observation.last_check = Some(status.project(current, observed_at));
            }
        }
        Ok(observation)
    }
}

impl Status {
    fn validate(&self, role: Role) -> Result<Option<Checkpoint>> {
        validate_active(role, &self.active)?;
        let stage_expected = matches!(
            self.disposition,
            Disposition::Ready
                | Disposition::OutsideMaintenance
                | Disposition::Hold
                | Disposition::Exhausted
        );
        let candidate_expected = stage_expected || self.disposition == Disposition::Current;
        if self.schema != STATUS_SCHEMA
            || !valid_channel(&self.channel)
            || self.policy_checkpoint.sequence == 0
            || !valid_digest(&self.policy_checkpoint.sha256)
            || self.candidate.is_some() != candidate_expected
            || self.staged.is_some() != stage_expected
            || self.candidate.as_ref().is_some_and(|candidate| {
                !valid_digest(&candidate.manifest_sha256)
                    || candidate.epoch < self.active.epoch
                    || match candidate.activation {
                        Activation::Routine => self.security_deadline_missed,
                        Activation::Security { activate_by } => activate_by <= 0,
                    }
            })
            || self.candidate.is_none() && self.security_deadline_missed
            || self.staged.as_ref().is_some_and(|staged| {
                !self
                    .candidate
                    .as_ref()
                    .is_some_and(|candidate| *staged == candidate.manifest_sha256)
            })
            || self.prepared_inactive_slot.is_some_and(|slot| {
                role != Role::Hypervisor || Some(slot) == self.active.slot || self.staged.is_none()
            })
            || self
                .delivered_trial
                .as_deref()
                .is_some_and(|trial| !valid_uuid(trial) || self.staged.is_none())
            || self
                .requested_trial
                .as_ref()
                .is_some_and(|trial| Some(trial) != self.delivered_trial.as_ref())
            || self.hold_until.is_some() != (self.disposition == Disposition::Hold)
            || self.hold_until.is_some_and(|until| until <= 0)
        {
            return Err(invalid("invalid recorded OS update status").into());
        }
        match (
            self.disposition == Disposition::Disabled,
            self.last_refresh,
            self.fresh_until,
            self.channel_sequence,
            self.head_sha256.as_ref(),
        ) {
            (true, None, None, None, None) if self.candidate.is_none() => Ok(None),
            (false, Some(start), Some(end), Some(sequence), Some(digest))
                if start > 0
                    && end > start
                    && sequence >= self.active.sequence
                    && valid_digest(digest) =>
            {
                Ok(Some(Checkpoint {
                    sequence,
                    sha256: digest.clone(),
                }))
            }
            _ => Err(invalid("invalid recorded OS authorization interval").into()),
        }
    }

    fn project(self, current: bool, observed_at: i64) -> Check {
        let freshness = if !current {
            Freshness::Superseded
        } else {
            match self.last_refresh.zip(self.fresh_until) {
                Some((start, _)) if observed_at < start => Freshness::ClockRegressed,
                Some((_, end)) if observed_at >= end => Freshness::Expired,
                Some(_) => Freshness::Fresh,
                None => Freshness::NotApplicable,
            }
        };
        Check {
            channel: self.channel,
            policy_revision: self.policy_checkpoint.sequence,
            disposition: self.disposition,
            freshness,
            last_refresh: self.last_refresh,
            fresh_until: self.fresh_until,
            channel_sequence: self.channel_sequence,
            candidate: self.candidate.map(|candidate| CandidateView {
                epoch: candidate.epoch,
                manifest_sha256: candidate.manifest_sha256,
                activation: candidate.activation,
            }),
            staged: self.staged,
            prepared_inactive_slot: self.prepared_inactive_slot,
            delivered_trial: self.delivered_trial,
            requested_trial: self.requested_trial,
            hold_until: self.hold_until,
            security_deadline_missed: self.security_deadline_missed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn check_visibility_does_not_extend_freshness() -> Result<()> {
        let receipt = json!({
            "schema": STATUS_SCHEMA, "channel": "stable", "disposition": "ready",
            "policy_checkpoint": {"sequence": 4, "sha256": "a".repeat(64)},
            "head_sha256": "b".repeat(64), "channel_sequence": 7,
            "active": {
                "role": "hypervisor", "slot": "a", "epoch": 3, "sequence": 6,
                "manifest_sha256": "c".repeat(64),
            },
            "candidate": {
                "epoch": 4, "manifest_sha256": "d".repeat(64),
                "activation": {"urgency": "security", "activate_by": 12},
            },
            "staged": "d".repeat(64), "last_refresh": 10, "fresh_until": 20,
            "prepared_inactive_slot": "b", "security_deadline_missed": false,
        });
        for (current, at, expected) in [
            (true, 10, Freshness::Fresh),
            (true, 19, Freshness::Fresh),
            (true, 20, Freshness::Expired),
            (true, 9, Freshness::ClockRegressed),
            (false, 11, Freshness::Superseded),
        ] {
            let record: Status = serde_json::from_value(receipt.clone())?;
            assert_eq!(
                record.validate(Role::Hypervisor)?.map(|head| head.sequence),
                Some(7)
            );
            assert!(record.validate(Role::ServiceGuest).is_err());
            let check = record.project(current, at);
            assert_eq!(check.freshness, expected);
            assert_eq!(check.staged.as_deref(), Some("d".repeat(64).as_str()));
        }
        Ok(())
    }
}
