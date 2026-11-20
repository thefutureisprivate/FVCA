//! Verify operational evidence independently of the distribution signature.

use std::fs::{self, File};
use std::path::Path;

use jiff::Timestamp;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tough::Repository;

use super::{Component, Offer, VendorAuthentication, capsule, label, transition};
use crate::{
    Result,
    channel::{Window, digest, target},
    invalid, state, valid_digest,
};

pub(super) const LIMIT: u64 = 8192;
const DISTRIBUTION: &str = "distribution";
const VENDOR: &str = "vendor";
const REBOOT: &str = "reboot-policy";
pub(super) const REBOOT_FILE: &str = "reboot-policy.json";
const RECOVERY: &str = "recovery";
pub(super) const RECOVERY_FILE: &str = "recovery.json";
pub(super) const FILES: [&str; 4] = [
    "distribution.json",
    "vendor.json",
    REBOOT_FILE,
    RECOVERY_FILE,
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Record<T> {
    schema: String,
    transition_sha256: String,
    evidence: T,
}

fn decode<T: DeserializeOwned>(
    bytes: &[u8],
    kind: &str,
    checksum: &str,
    offer: &Offer,
) -> Result<T> {
    if bytes.len() as u64 > LIMIT || digest(bytes) != checksum {
        return Err(invalid(&format!(
            "firmware {kind} evidence differs from the signed offer"
        ))
        .into());
    }
    let record: Record<T> = serde_json::from_slice(bytes)?;
    if record.schema != format!("fvca-firmware-{kind}-v1")
        || record.transition_sha256 != offer.qualification.transition_evidence_sha256
    {
        return Err(invalid(&format!(
            "firmware {kind} evidence differs from the qualified transition"
        ))
        .into());
    }
    Ok(record.evidence)
}

async fn fetch<T: DeserializeOwned>(
    repo: &Repository,
    kind: &str,
    checksum: &str,
    offer: &Offer,
) -> Result<(Vec<u8>, T)> {
    let bytes = target(repo, format!("fvca-firmware-{kind}-{checksum}.json"), LIMIT).await?;
    let record = decode(&bytes, kind, checksum, offer)?;
    Ok((bytes, record))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Distribution {
    remote: String,
    metadata_sha256: String,
    signature_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Vendor {
    authentication: VendorAuthentication,
    procedure: String,
    signer_sha256: Option<String>,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Delivery {
    CapsuleOnDisk,
    FwupdEfi,
    OfflineNvme,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum Power {
    NoAdditionalRequirement,
    MainsRequired,
    ContinuityRequired,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Urgency {
    Routine,
    Security,
}

#[derive(Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum Step {
    Reboot,
    Shutdown,
    PowerCycle,
    Replug,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Reboot {
    pub(super) urgency: Urgency,
    delivery: Delivery,
    power: Power,
    steps: Vec<Step>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum RecoveryMethod {
    DualImage,
    VendorProcedure,
    PhysicalRepair,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Recovery {
    method: RecoveryMethod,
    procedure: String,
    qualified_retries: u8,
}

impl Recovery {
    pub(super) fn parse(bytes: &[u8], offer: &Offer) -> Result<Self> {
        let record: Self = decode(
            bytes,
            RECOVERY,
            &offer.qualification.recovery_evidence_sha256,
            offer,
        )?;
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> Result<()> {
        if !label(&self.procedure, 256)
            || (matches!(self.method, RecoveryMethod::PhysicalRepair)
                && self.qualified_retries != 0)
        {
            return Err(invalid("invalid qualified firmware recovery procedure").into());
        }
        Ok(())
    }
}

pub(super) struct Qualified {
    pub(super) records: [Vec<u8>; 4],
    pub(super) reboot: Reboot,
}

pub(super) async fn download(repo: &Repository, offer: &Offer) -> Result<Qualified> {
    let digests = &offer.qualification;
    let (distribution, dist): (_, Distribution) = fetch(
        repo,
        DISTRIBUTION,
        &digests.distribution_evidence_sha256,
        offer,
    )
    .await?;
    if dist.remote != offer.remote
        || dist.metadata_sha256 != offer.catalog.metadata.sha256
        || dist.signature_sha256 != offer.catalog.signature.sha256
    {
        return Err(
            invalid("firmware distribution evidence differs from the selected catalog").into(),
        );
    }
    let (vendor, vendor_record): (_, Vendor) =
        fetch(repo, VENDOR, &digests.vendor_evidence_sha256, offer).await?;
    if vendor_record.authentication != digests.vendor_authentication
        || !label(&vendor_record.procedure, 256)
        || vendor_record
            .signer_sha256
            .as_deref()
            .is_some_and(|sha| !valid_digest(sha))
        || (vendor_record.authentication
            == VendorAuthentication::IndependentlyVerifiedVendorSignature
            && vendor_record.signer_sha256.is_none())
    {
        return Err(invalid("invalid qualified vendor authentication evidence").into());
    }
    let (reboot, reboot_record): (_, Reboot) =
        fetch(repo, REBOOT, &digests.reboot_policy_sha256, offer).await?;
    if matches!(reboot_record.delivery, Delivery::OfflineNvme)
        != matches!(offer.device.component, Component::Nvme)
    {
        return Err(
            invalid("firmware reboot policy differs from the selected device protocol").into(),
        );
    }
    let (recovery, recovery_record): (_, Recovery) =
        fetch(repo, RECOVERY, &digests.recovery_evidence_sha256, offer).await?;
    recovery_record.validate()?;
    Ok(Qualified {
        records: [distribution, vendor, reboot, recovery],
        reboot: reboot_record,
    })
}

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub(super) enum Status {
    Blocked { reason: String },
    RecoveryNeeded { reason: &'static str },
    AwaitingMaintenance,
    ChecksSatisfied,
}

impl Reboot {
    pub(super) fn require_capsule_reboot(bytes: &[u8], offer: &Offer) -> Result<()> {
        let reboot: Self = decode(
            bytes,
            REBOOT,
            &offer.qualification.reboot_policy_sha256,
            offer,
        )?;
        if let Some(reason) = reboot.delivery_blocker() {
            return Err(invalid(reason).into());
        }
        Ok(())
    }

    pub(super) fn preflight(
        &self,
        key_release: transition::KeyRelease,
        boot: &transition::Status,
        capsule: Option<&capsule::Delivery>,
        requires_ac: bool,
        window: &Window,
        now: Timestamp,
    ) -> Result<Status> {
        if let Some(reason) = self.delivery_blocker() {
            return Ok(Status::blocked(reason));
        }
        if key_release == transition::KeyRelease::RequiresPreparation {
            return Ok(Status::RecoveryNeeded {
                reason: "qualified TPM key release requires separately authorized preparation",
            });
        }
        if !matches!(boot, transition::Status::Matched) {
            return Ok(Status::blocked(
                "qualified boot and storage checks are pending",
            ));
        }
        if !capsule.is_some_and(capsule::Delivery::matched) {
            return Ok(Status::blocked(
                "the qualified capsule delivery route is unavailable",
            ));
        }
        self.power_and_schedule(requires_ac, window, now, live_mains)
    }

    fn delivery_blocker(&self) -> Option<&'static str> {
        match self.delivery {
            Delivery::FwupdEfi => Some("the qualified fwupd EFI helper route is unavailable"),
            Delivery::OfflineNvme => {
                Some("the qualified offline NVMe activation route is unavailable")
            }
            Delivery::CapsuleOnDisk if self.steps != [Step::Reboot] => {
                Some("the qualified firmware power-transition sequence is unavailable")
            }
            Delivery::CapsuleOnDisk => None,
        }
    }

    fn power_and_schedule(
        &self,
        requires_ac: bool,
        window: &Window,
        now: Timestamp,
        mains: impl FnOnce() -> Result<bool>,
    ) -> Result<Status> {
        if self.power == Power::ContinuityRequired {
            return Ok(Status::blocked(
                "qualified power-continuity telemetry is unavailable",
            ));
        }
        if requires_ac || self.power == Power::MainsRequired {
            match mains() {
                Ok(true) => (),
                Ok(false) => return Ok(Status::blocked("required mains power is not online")),
                Err(error) => {
                    return Ok(Status::blocked(&format!(
                        "mains power observation: {error}"
                    )));
                }
            }
        }
        if self.urgency == Urgency::Routine && !window.contains(now, window.timezone()?) {
            return Ok(Status::AwaitingMaintenance);
        }
        Ok(Status::ChecksSatisfied)
    }
}

impl Status {
    pub(super) fn blocked(reason: &str) -> Self {
        Self::Blocked {
            reason: reason.into(),
        }
    }
}

fn live_mains() -> Result<bool> {
    let supplies = Path::new("/sys/class/power_supply");
    const SYSFS_MAGIC: u64 = 0x62656572;
    if rustix::fs::fstatfs(File::open(supplies)?)?.f_type as u64 != SYSFS_MAGIC {
        return Err(invalid("power supply class is outside kernel sysfs").into());
    }
    read_mains(supplies, Path::new("/sys/devices"))
}

fn read_mains(supplies: &Path, devices: &Path) -> Result<bool> {
    for entry in fs::read_dir(supplies)? {
        let path = fs::canonicalize(entry?.path())?;
        if !path.starts_with(devices) {
            return Err(invalid("power supply is outside kernel devices").into());
        }
        if state::read(&path.join("type"), 64)? != b"Mains\n" {
            continue;
        }
        match state::read(&path.join("online"), 2)?.as_slice() {
            b"1\n" => return Ok(true),
            b"0\n" => (),
            _ => return Err(invalid("invalid mains power status").into()),
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn security_urgency_bypasses_only_the_window() -> Result<()> {
        let window = Window::default();
        let outside: Timestamp = "2026-10-25T01:05:00Z".parse()?;
        let inside: Timestamp = "2026-10-25T03:05:00Z".parse()?;
        let mut reboot = Reboot {
            urgency: Urgency::Routine,
            delivery: Delivery::CapsuleOnDisk,
            power: Power::NoAdditionalRequirement,
            steps: vec![Step::Reboot],
        };
        assert!(reboot.delivery_blocker().is_none());
        assert!(matches!(
            reboot.power_and_schedule(false, &window, outside, || unreachable!())?,
            Status::AwaitingMaintenance
        ));
        assert!(matches!(
            reboot.power_and_schedule(false, &window, inside, || unreachable!())?,
            Status::ChecksSatisfied
        ));
        reboot.urgency = Urgency::Security;
        assert!(matches!(
            reboot.power_and_schedule(false, &window, outside, || unreachable!())?,
            Status::ChecksSatisfied
        ));
        assert!(matches!(
            reboot.power_and_schedule(true, &window, outside, || Ok(false))?,
            Status::Blocked { .. }
        ));
        reboot.power = Power::MainsRequired;
        assert!(matches!(
            reboot.power_and_schedule(false, &window, outside, || Ok(true))?,
            Status::ChecksSatisfied
        ));
        reboot.power = Power::ContinuityRequired;
        assert!(matches!(
            reboot.power_and_schedule(false, &window, outside, || unreachable!())?,
            Status::Blocked { .. }
        ));
        reboot.steps.push(Step::PowerCycle);
        assert!(reboot.delivery_blocker().is_some());
        Ok(())
    }

    #[test]
    fn changed_tpm_enrollment_requires_recovery_preparation() -> Result<()> {
        let reboot = Reboot {
            urgency: Urgency::Security,
            delivery: Delivery::CapsuleOnDisk,
            power: Power::NoAdditionalRequirement,
            steps: vec![Step::Reboot],
        };
        assert!(matches!(
            reboot.preflight(
                transition::KeyRelease::RequiresPreparation,
                &transition::Status::Matched,
                None,
                false,
                &Window::default(),
                Timestamp::now(),
            )?,
            Status::RecoveryNeeded { .. }
        ));
        Ok(())
    }

    #[test]
    fn mains_observation_requires_an_online_mains_supply() -> Result<()> {
        let work = tempfile::tempdir()?;
        let supplies = work.path().join("power_supply");
        let devices = work.path().join("devices");
        fs::create_dir(&supplies)?;
        let supply = devices.join("supply");
        fs::create_dir_all(&supply)?;
        symlink(&supply, supplies.join("AC"))?;
        fs::write(supply.join("type"), "Battery\n")?;
        fs::write(supply.join("online"), "1\n")?;
        assert!(!read_mains(&supplies, &devices)?);
        fs::write(supply.join("type"), "Mains\n")?;
        assert!(read_mains(&supplies, &devices)?);
        fs::write(supply.join("online"), "0\n")?;
        assert!(!read_mains(&supplies, &devices)?);
        fs::write(supply.join("online"), "2\n")?;
        assert!(read_mains(&supplies, &devices).is_err());
        Ok(())
    }
}
