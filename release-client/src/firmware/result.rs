//! Correlate post-boot firmware observations with the staged activation.

use std::fs::File;
use std::io::Read;

use rustix::fs::{self, Mode, OFlags, ResolveFlags};
use serde::Serialize;

use super::{
    Esrt, HEAD_SCHEMA, Head, OFFER, Offer, Version, activation::Activation, boot, boot_id, live,
    uuid,
};
use crate::{MANIFEST_BYTES, Result, Role, channel::digest, handoff, invalid};

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub(super) enum Evidence {
    SameBoot {
        boot_id: String,
    },
    Unavailable {
        boot_id: Option<String>,
        reason: String,
    },
    Observed {
        boot_id: String,
        assessment: Assessment,
        boot_evidence: boot::Evidence,
        #[serde(flatten)]
        observed: Observed,
    },
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Assessment {
    TargetReported,
    AttemptFailed,
    NoMatchingAttempt,
    ConflictingReports,
    TransitionPending,
    VersionOnly,
}

#[derive(Serialize)]
pub(super) struct Observed {
    pub(super) version: Version,
    pub(super) esrt: Option<Esrt>,
    pub(super) transition_pending: bool,
}

pub(super) fn inspect(directory: &File, activation: &Activation) -> Evidence {
    let boot = match boot_id() {
        Ok(boot) if boot == activation.boot_id => return Evidence::SameBoot { boot_id: boot },
        Ok(boot) => boot,
        Err(error) => {
            return Evidence::Unavailable {
                boot_id: None,
                reason: error.to_string(),
            };
        }
    };
    let observed = collect(directory, activation);
    match observed {
        Ok((assessment, observed)) => Evidence::Observed {
            boot_evidence: boot::inspect(directory, &boot),
            boot_id: boot,
            assessment,
            observed,
        },
        Err(error) => Evidence::Unavailable {
            boot_id: Some(boot),
            reason: error.to_string(),
        },
    }
}

fn collect(directory: &File, activation: &Activation) -> Result<(Assessment, Observed)> {
    let relative = format!("staged/{}/{OFFER}", activation.offer_sha256);
    let file = File::from(fs::openat2(
        directory,
        relative.as_str(),
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
    )?);
    handoff::private_file(&file)?;
    let mut bytes = Vec::new();
    file.take(MANIFEST_BYTES + 1).read_to_end(&mut bytes)?;
    let (head, offer) = parse_offer(&bytes, &activation.offer_sha256, &activation.device_id)?;
    require_baseline(&offer, activation.esrt_before.as_ref())?;
    let observed = live::read_result(&offer, &head.system_uuid, &head.fwupd_version)?;
    let assessment = assess(&offer, &observed);
    Ok((assessment, observed))
}

fn parse_offer(bytes: &[u8], sha256: &str, device_id: &str) -> Result<(Head, Offer)> {
    // The activation pins the exact offer at admission. Recovery stays bound
    // to those bytes even when the current channel is withdrawn or expired.
    if bytes.len() as u64 > MANIFEST_BYTES || digest(bytes) != sha256 {
        return Err(invalid("staged firmware offer differs from the activation digest").into());
    }
    let mut head: Head = serde_json::from_slice(bytes)?;
    let offer = head
        .offer
        .take()
        .ok_or_else(|| invalid("activation requires a staged firmware offer"))?;
    if head.schema != HEAD_SCHEMA
        || head.role != Role::Hypervisor
        || !uuid(&head.system_uuid)
        || offer.device.device_id != device_id
        || !offer.device.valid()
        || !offer.valid_transition()
    {
        return Err(invalid("staged firmware offer differs from the activation identity").into());
    }
    Ok((head, offer))
}

fn require_baseline(offer: &Offer, before: Option<&Esrt>) -> Result<()> {
    match (offer.device.component.esrt_type(), before) {
        (None, None) => Ok(()),
        (Some(kind), Some(before))
            if before.guid == offer.device.guid
                && before.fw_type == kind
                && Some(before.fw_version) == offer.from.raw
                && Some(before.last_attempt_version) != offer.to.raw =>
        {
            Ok(())
        }
        _ => Err(invalid("activation lacks an exact pre-flash ESRT baseline").into()),
    }
}

pub(super) fn assess(offer: &Offer, observed: &Observed) -> Assessment {
    if observed.transition_pending {
        return Assessment::TransitionPending;
    }
    let Some(esrt) = observed.esrt.as_ref() else {
        return Assessment::VersionOnly;
    };
    if observed.version.raw != Some(esrt.fw_version)
        || esrt.fw_version < esrt.lowest_supported_fw_version
    {
        return Assessment::ConflictingReports;
    }
    if Some(esrt.last_attempt_version) != offer.to.raw {
        return Assessment::NoMatchingAttempt;
    }
    match (&observed.version, esrt.last_attempt_status) {
        (version, 0) if version == &offer.to => Assessment::TargetReported,
        (version, status) if version == &offer.from && status != 0 => Assessment::AttemptFailed,
        _ => Assessment::ConflictingReports,
    }
}

#[cfg(test)]
pub(super) fn test_offer() -> serde_json::Value {
    serde_json::json!({
        "schema": HEAD_SCHEMA,
        "role": "hypervisor",
        "channel": "test",
        "sequence": 4,
        "valid_from": 1,
        "expires": 2,
        "system_uuid": "d0290b27-4076-4122-9600-a3bb1936ac38",
        "fwupd_version": "2.0.20",
        "offer": {
            "device": {
                "component": "system-firmware",
                "device_id": "a".repeat(40),
                "guid": "a1234567-d234-4031-a111-000000000000",
                "model": "System Firmware",
                "vendor_id": "DMI:Fixture",
                "serial_sha256": null,
                "version_format": "pair"
            },
            "remote": "lvfs",
            "epoch": 1,
            "from": { "text": "1.42", "raw": 65578 },
            "to": { "text": "1.51", "raw": 65587 },
            "archive": { "sha256": "1".repeat(64), "bytes": 19 },
            "payload_sha256": "2".repeat(64),
            "catalog": {
                "metadata": { "sha256": "3".repeat(64), "bytes": 9 },
                "signature": { "sha256": "4".repeat(64), "bytes": 9 }
            },
            "qualification": {
                "distribution_evidence_sha256": "5".repeat(64),
                "vendor_authentication": "device-signature",
                "vendor_evidence_sha256": "6".repeat(64),
                "transition_evidence_sha256": "7".repeat(64),
                "reboot_policy_sha256": "8".repeat(64),
                "recovery_evidence_sha256": "9".repeat(64)
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binds_recovery_to_the_original_offer_and_pre_flash_esrt() -> Result<()> {
        let document = serde_json::to_vec(&test_offer())?;
        let (head, offer) = parse_offer(&document, &digest(&document), &"a".repeat(40))?;
        assert_eq!(head.expires, 2);
        assert!(parse_offer(&document, &"0".repeat(64), &"a".repeat(40)).is_err());
        assert!(parse_offer(&document, &digest(&document), &"b".repeat(40)).is_err());
        assert!(require_baseline(&offer, None).is_err());
        let mut before = Esrt {
            guid: offer.device.guid.clone(),
            fw_type: 1,
            fw_version: 65578,
            lowest_supported_fw_version: 65578,
            capsule_flags: 0x50000,
            last_attempt_version: 65578,
            last_attempt_status: 0,
        };
        require_baseline(&offer, Some(&before))?;
        before.last_attempt_version = 65587;
        assert!(require_baseline(&offer, Some(&before)).is_err());
        Ok(())
    }

    #[test]
    fn distinguishes_firmware_reports_without_treating_them_as_verified_success() -> Result<()> {
        let head: Head = serde_json::from_value(test_offer())?;
        let offer = head.offer.unwrap();
        for (installed, attempt, status, version, pending, assessment) in [
            (65587, 65587, 0, "1.51", false, Assessment::TargetReported),
            (65578, 65587, 5, "1.42", false, Assessment::AttemptFailed),
            (65578, 0, 5, "1.42", false, Assessment::NoMatchingAttempt),
            (
                65578,
                65578,
                0,
                "1.42",
                false,
                Assessment::NoMatchingAttempt,
            ),
            (
                65587,
                65587,
                5,
                "1.51",
                false,
                Assessment::ConflictingReports,
            ),
            (
                65578,
                65587,
                0,
                "1.42",
                false,
                Assessment::ConflictingReports,
            ),
            (65587, 65587, 0, "1.51", true, Assessment::TransitionPending),
        ] {
            let observed = Observed {
                version: Version {
                    text: version.into(),
                    raw: Some(installed),
                },
                esrt: Some(Esrt {
                    guid: offer.device.guid.clone(),
                    fw_type: 1,
                    fw_version: installed,
                    lowest_supported_fw_version: 65578,
                    capsule_flags: 0x50000,
                    last_attempt_version: attempt,
                    last_attempt_status: status,
                }),
                transition_pending: pending,
            };
            assert_eq!(assess(&offer, &observed), assessment);
        }
        Ok(())
    }
}
