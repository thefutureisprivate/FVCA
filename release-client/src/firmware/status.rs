//! Read bounded firmware observations without accessing the daemon or lifecycle APIs.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use rustix::fs::OFlags;
use serde::{Deserialize, Serialize};

use super::{ENROLLMENT, HEAD_SCHEMA, Head, OFFER, STATUS, activation, result};
use crate::{
    MANIFEST_BYTES, Result, Role, channel::digest, handoff, invalid, state, valid_digest,
    valid_uuid,
};

const VIEW_SCHEMA: &str = "fvca-host-firmware-status-v1";
const CHECK_SCHEMA: &str = "fvca-firmware-discovery-status-v1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StatusSnapshot {
    schema: String,
    enrolled: bool,
    activation: Option<Active>,
    last_check: Option<Check>,
    last_check_unavailable: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Active {
    transaction: String,
    device_id: String,
    offer_sha256: String,
    phase: activation::Phase,
}

impl Active {
    fn valid(&self) -> bool {
        valid_uuid(&self.transaction)
            && super::lower_hex(&self.device_id, 40)
            && valid_digest(&self.offer_sha256)
    }
}

impl From<activation::Activation> for Active {
    fn from(active: activation::Activation) -> Self {
        Self {
            transaction: active.transaction,
            device_id: active.device_id,
            offer_sha256: active.offer_sha256,
            phase: active.phase,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Check {
    disposition: Disposition,
    checked_at: i64,
    channel_sequence: Option<u64>,
    fresh_until: Option<i64>,
    staged: Option<Staged>,
    operation: Option<Active>,
    assessment: Option<result::Assessment>,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Disposition {
    Checking,
    NoOffer,
    Staged,
    Blocked,
    Draining,
    Flashing,
    RebootPending,
    PowerTransitionPending,
    OutcomeUnknown,
    Failed,
    VerifiedSuccess,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Staged {
    device_id: String,
    offer_sha256: String,
    archive_sha256: String,
    qualified_from: String,
    target: String,
    eligibility: Option<Eligibility>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Eligibility {
    Blocked,
    RecoveryNeeded,
    AwaitingMaintenance,
    ChecksSatisfied,
}

#[derive(Deserialize)]
struct SavedCheck {
    schema: String,
    disposition: Disposition,
    checked_at: i64,
    channel_sequence: Option<u64>,
    fresh_until: Option<i64>,
    offer_sha256: Option<String>,
    operational_preflight: Option<Preflight>,
    activation: Option<activation::Activation>,
    recovery_evidence: Option<Observed>,
}

#[derive(Deserialize)]
struct Preflight {
    state: Eligibility,
}

#[derive(Deserialize)]
struct Observed {
    assessment: Option<result::Assessment>,
}

impl StatusSnapshot {
    pub(crate) fn read() -> Result<Self> {
        let enrolled = match state::read(Path::new("/run/fvca/firmware-update-owner"), 32) {
            Ok(bytes) if bytes.len() == 32 && bytes.iter().any(|byte| *byte != 0) => true,
            Ok(_) => return Err(invalid("invalid firmware enrollment marker").into()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        let (activation, last_check) = if enrolled {
            let path = Path::new("/run/fvca/host-data").join(ENROLLMENT);
            let pool = handoff::require_pool_directory(&path)?;
            let activation = activation::pending(&pool)?.map(Active::from);
            (activation, read_check(&pool))
        } else if fvca_trial_authorization::firmware::activation_pending()? {
            return Err(invalid("pending firmware activation has no current enrollment").into());
        } else {
            (None, Ok(None))
        };
        let last_check_unavailable = last_check.is_err();
        Ok(Self {
            schema: VIEW_SCHEMA.into(),
            enrolled,
            activation,
            last_check: last_check.unwrap_or_default(),
            last_check_unavailable,
        })
    }
}

fn read_check(pool: &File) -> Result<Option<Check>> {
    let file = match handoff::open_child(
        pool,
        STATUS,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY,
    ) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    handoff::private_file(&file)?;
    let mut bytes = Vec::new();
    file.take(MANIFEST_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MANIFEST_BYTES {
        return Err(invalid("firmware check record exceeds its limit").into());
    }
    let saved: SavedCheck = serde_json::from_slice(&bytes)?;
    if saved.schema != CHECK_SCHEMA || saved.checked_at <= 0 || saved.channel_sequence == Some(0) {
        return Err(invalid("invalid firmware check record").into());
    }
    let staged = match saved.disposition {
        Disposition::Staged => Some(read_stage(
            pool,
            saved.offer_sha256,
            saved.operational_preflight,
        )?),
        _ => None,
    };
    let operation = saved.activation.map(Active::from);
    if operation
        .as_ref()
        .is_some_and(|operation| !operation.valid())
    {
        return Err(invalid("firmware check recorded an invalid operation identity").into());
    }
    Ok(Some(Check {
        disposition: saved.disposition,
        checked_at: saved.checked_at,
        channel_sequence: saved.channel_sequence,
        fresh_until: saved.fresh_until,
        staged,
        operation,
        assessment: saved
            .recovery_evidence
            .and_then(|evidence| evidence.assessment),
    }))
}

fn read_stage(
    pool: &File,
    identity: Option<String>,
    preflight: Option<Preflight>,
) -> Result<Staged> {
    let offer_sha256 = identity
        .filter(|identity| valid_digest(identity))
        .ok_or_else(|| invalid("invalid staged firmware offer identity"))?;
    let directory = activation::staged_offer(pool, &offer_sha256)?;
    let file = result::staged_record(&directory, OFFER, MANIFEST_BYTES)?;
    if digest(&file) != offer_sha256 {
        return Err(invalid("firmware check does not match the stage it observed").into());
    }
    let head: Head = serde_json::from_slice(&file)?;
    if head.schema != HEAD_SCHEMA || head.role != Role::Hypervisor {
        return Err(invalid("invalid staged firmware offer schema or role").into());
    }
    let offer = head
        .offer
        .filter(|offer| {
            offer.device.valid() && offer.valid_transition() && valid_digest(&offer.archive.sha256)
        })
        .ok_or_else(|| invalid("firmware check does not match the stage it observed"))?;
    Ok(Staged {
        device_id: offer.device.device_id,
        offer_sha256,
        archive_sha256: offer.archive.sha256,
        qualified_from: offer.from.text,
        target: offer.to.text,
        eligibility: preflight.map(|entry| entry.state),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_recovery_assessment_without_internal_evidence() -> Result<()> {
        let work = tempfile::tempdir()?;
        super::super::save(
            work.path(),
            STATUS,
            &serde_json::json!({
                "schema": CHECK_SCHEMA, "disposition": "outcome-unknown", "checked_at": 100,
                "activation": {
                    "schema": "fvca-firmware-activation-v2",
                    "transaction": "dce9f9d8-344d-418c-870b-8784cbdf76ef",
                    "device_id": "b".repeat(40), "offer_sha256": "c".repeat(64),
                    "phase": "outcome-unknown", "boot_id": "bed953b9-9e25-4491-b95e-d8c98ff80dc5",
                    "guest_was_active": false, "mains_required": true
                },
                "completion_blocker": "/private/recovery/notes",
                "recovery_evidence": {
                    "state": "observed", "assessment": "conflicting-reports",
                    "boot_evidence": {"filesystem": "private identity"}
                },
            }),
        )?;
        let view = read_check(&File::open(work.path())?)?.unwrap();
        assert_eq!(
            serde_json::to_value(view)?,
            serde_json::json!({
                "disposition": "outcome-unknown", "checked_at": 100,
                "channel_sequence": null, "fresh_until": null, "staged": null,
                "assessment": "conflicting-reports",
                "operation": {
                    "transaction": "dce9f9d8-344d-418c-870b-8784cbdf76ef",
                    "device_id": "b".repeat(40), "offer_sha256": "c".repeat(64),
                    "phase": "outcome-unknown"
                },
            })
        );
        Ok(())
    }
}
