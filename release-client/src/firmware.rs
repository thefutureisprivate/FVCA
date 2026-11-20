//! Authenticate an exact Host firmware offer and stage its cabinet for qualification.

use std::fs::{self, File, Permissions};
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use tough::schema::key::Key;
use tough::{Repository, TargetName};

use crate::channel::{checkpoint, digest, target, verify};
use crate::depot::{CONFIG_BYTES, Depot, METADATA_BYTES};
use crate::{
    MANIFEST_BYTES, Member, Result, Role, check_target, download, invalid, load_repository,
    output_file, state, valid_digest, verify_member,
};

const ARCHIVE_LIMIT: u64 = 256 * 1024 * 1024;
const OBSERVATION_LIMIT: u64 = 1024 * 1024;
const OBSERVATION_AGE: i64 = 300;
const OFFER: &str = "offer.json";
const SIGNATURE: &str = "offer.sig";
const ARCHIVE: &str = "firmware.cab";

#[derive(Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct Platform {
    system_uuid: String,
    vendor: String,
    product: String,
    board: String,
    board_revision: String,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum Component {
    SystemFirmware,
    EmbeddedController,
    Nvme,
}

impl Component {
    fn plugin(self) -> &'static str {
        match self {
            Self::SystemFirmware | Self::EmbeddedController => "uefi_capsule",
            Self::Nvme => "nvme",
        }
    }

    fn protocol(self) -> &'static str {
        match self {
            Self::SystemFirmware | Self::EmbeddedController => "org.uefi.capsule",
            Self::Nvme => "org.nvmexpress",
        }
    }

    fn esrt_type(self) -> Option<u8> {
        match self {
            Self::SystemFirmware => Some(1),
            Self::EmbeddedController => Some(2),
            Self::Nvme => None,
        }
    }
}

#[derive(Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct DeviceIdentity {
    component: Component,
    device_id: String,
    guid: String,
    model: String,
    vendor_id: String,
    serial_sha256: Option<String>,
    version_format: String,
}

impl DeviceIdentity {
    fn valid(&self) -> bool {
        lower_hex(&self.device_id, 40)
            && uuid(&self.guid)
            && label(&self.model, 128)
            && label(&self.vendor_id, 64)
            && match self.component {
                Component::Nvme => {
                    self.version_format == "plain"
                        && self
                            .vendor_id
                            .strip_prefix("PCI:0x")
                            .or_else(|| self.vendor_id.strip_prefix("NVME:0x"))
                            .is_some_and(|id| lower_hex(id, 4))
                        && self.serial_sha256.as_deref().is_some_and(valid_digest)
                }
                Component::SystemFirmware | Component::EmbeddedController => {
                    matches!(
                        self.version_format.as_str(),
                        "number" | "pair" | "triplet" | "quad"
                    ) && self.vendor_id.starts_with("DMI:")
                        && self.model
                            == if self.component == Component::SystemFirmware {
                                "System Firmware"
                            } else {
                                "Embedded Controller"
                            }
                        && self.serial_sha256.is_none()
                }
            }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    schema: String,
    role: Role,
    revision: u64,
    valid_from: i64,
    expires: i64,
    channel: String,
    platform: Platform,
    fwupd_version: String,
    tuf_root_sha256: String,
    depot_config_sha256: String,
    qualification_key_ed25519: String,
    max_archive_bytes: u64,
    allowed_devices: Vec<DeviceIdentity>,
    allowed_remotes: Vec<String>,
    minimum_epoch: u64,
}

impl Policy {
    fn validate(&self, now: i64) -> Result<()> {
        if self.schema != "fvca-firmware-policy-v1"
            || self.role != Role::Hypervisor
            || self.revision == 0
            || !current(self.valid_from, self.expires, now)
            || !name(&self.channel)
            || !uuid(&self.platform.system_uuid)
            || [
                &self.platform.vendor,
                &self.platform.product,
                &self.platform.board,
                &self.platform.board_revision,
                &self.fwupd_version,
            ]
            .iter()
            .any(|value| !label(value, 128))
            || !(1..=ARCHIVE_LIMIT).contains(&self.max_archive_bytes)
            || self.minimum_epoch == 0
            || self.allowed_devices.len() > 64
            || self
                .allowed_devices
                .iter()
                .enumerate()
                .any(|(index, device)| {
                    !device.valid()
                        || self.allowed_devices[..index]
                            .iter()
                            .any(|prior| prior.device_id == device.device_id)
                })
            || self.allowed_remotes.iter().any(|remote| !name(remote))
            || [
                &self.tuf_root_sha256,
                &self.depot_config_sha256,
                &self.qualification_key_ed25519,
            ]
            .iter()
            .any(|value| !valid_digest(value))
        {
            return Err(invalid("invalid or expired standing Host firmware policy").into());
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    schema: String,
    observed_at: i64,
    platform: Platform,
    fwupd_version: String,
    devices: Devices,
    upgrades: Devices,
    esrt: Vec<Esrt>,
}

#[derive(Deserialize)]
struct Devices {
    #[serde(rename = "Devices")]
    devices: Vec<ObservedDevice>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Esrt {
    guid: String,
    fw_type: u8,
    fw_version: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ObservedDevice {
    device_id: String,
    name: Option<String>,
    plugin: Option<String>,
    #[serde(default)]
    guid: Vec<String>,
    #[serde(default)]
    protocols: Vec<String>,
    #[serde(default)]
    vendor_ids: Vec<String>,
    serial: Option<String>,
    version: Option<String>,
    version_raw: Option<u64>,
    version_format: Option<String>,
    #[serde(default)]
    flags: Vec<String>,
    #[serde(default)]
    problems: Vec<String>,
    #[serde(default)]
    releases: Vec<ObservedRelease>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ObservedRelease {
    version: Option<String>,
    remote_id: Option<String>,
    protocol: Option<String>,
    #[serde(default)]
    checksum: Vec<String>,
    #[serde(default)]
    flags: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Version {
    text: String,
    raw: Option<u32>,
}

impl Version {
    fn matches_format(&self, format: &str) -> bool {
        let Some(raw) = self.raw else {
            return format == "plain" && label(&self.text, 64);
        };
        let [a, b, c, d] = raw.to_be_bytes();
        let expected = match format {
            "number" => raw.to_string(),
            "pair" => format!("{}.{}", raw >> 16, raw & 0xffff),
            "triplet" => format!("{a}.{b}.{}", raw & 0xffff),
            "quad" => format!("{a}.{b}.{c}.{d}"),
            _ => return false,
        };
        self.text == expected
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum VendorAuthentication {
    DeviceSignature,
    IndependentlyVerifiedVendorSignature,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Qualification {
    distribution_evidence_sha256: String,
    vendor_authentication: VendorAuthentication,
    vendor_evidence_sha256: String,
    transition_evidence_sha256: String,
    reboot_policy_sha256: String,
    recovery_evidence_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Offer {
    schema: String,
    role: Role,
    channel: String,
    sequence: u64,
    valid_from: i64,
    expires: i64,
    system_uuid: String,
    fwupd_version: String,
    device: DeviceIdentity,
    remote: String,
    epoch: u64,
    from: Version,
    to: Version,
    archive: Member,
    payload_sha256: String,
    qualification: Qualification,
}

impl Offer {
    fn require_scope(&self, policy: &Policy, now: i64) -> Result<()> {
        if self.schema != "fvca-firmware-offer-v1"
            || self.role != Role::Hypervisor
            || self.channel != policy.channel
            || self.sequence == 0
            || !current(self.valid_from, self.expires, now)
            || self.expires - self.valid_from > 7 * 86_400
            || self.system_uuid != policy.platform.system_uuid
            || self.fwupd_version != policy.fwupd_version
            || !policy.allowed_devices.contains(&self.device)
            || !policy.allowed_remotes.contains(&self.remote)
            || self.epoch < policy.minimum_epoch
            || !(1..=policy.max_archive_bytes).contains(&self.archive.bytes)
            || !valid_digest(&self.archive.sha256)
            || !valid_digest(&self.payload_sha256)
        {
            return Err(invalid("firmware offer is outside the signed Host policy").into());
        }
        let format = &self.device.version_format;
        if !self.from.matches_format(format)
            || !self.to.matches_format(format)
            || self.from.text == self.to.text
            || match self.device.component.esrt_type() {
                Some(_) => {
                    !matches!((self.from.raw, self.to.raw), (Some(from), Some(to)) if from < to)
                }
                None => self.from.raw.is_some() || self.to.raw.is_some(),
            }
        {
            return Err(invalid("firmware offer has an invalid version transition").into());
        }
        let evidence = &self.qualification;
        if [
            &evidence.distribution_evidence_sha256,
            &evidence.vendor_evidence_sha256,
            &evidence.transition_evidence_sha256,
            &evidence.reboot_policy_sha256,
            &evidence.recovery_evidence_sha256,
        ]
        .iter()
        .any(|value| !valid_digest(value))
            || evidence.distribution_evidence_sha256 == evidence.vendor_evidence_sha256
        {
            return Err(invalid(
                "firmware offer lacks independent transition or authentication evidence",
            )
            .into());
        }
        Ok(())
    }

    fn require_observation(&self, policy: &Policy, observed: &Observation, now: i64) -> Result<()> {
        if observed.schema != "fvca-firmware-observation-v1"
            || observed.platform != policy.platform
            || observed.fwupd_version != policy.fwupd_version
            || observed.observed_at <= 0
            || !(observed.observed_at..observed.observed_at.saturating_add(OBSERVATION_AGE))
                .contains(&now)
        {
            return Err(invalid(
                "firmware observation is stale or differs from the enrolled platform",
            )
            .into());
        }
        self.check_device(unique_device(&observed.devices, &self.device.device_id)?)?;
        let upgrade = unique_device(&observed.upgrades, &self.device.device_id)?;
        self.check_device(upgrade)?;
        let release = unique(
            upgrade.releases.iter().filter(|release| {
                release.version.as_deref() == Some(&self.to.text)
                    && release.remote_id.as_deref() == Some(&self.remote)
                    && release.protocol.as_deref() == Some(self.device.component.protocol())
                    && release.checksum.contains(&self.archive.sha256)
            }),
            "fwupd does not list the exact qualified upgrade",
        )?;
        if !has(&release.flags, "trusted-metadata")
            || !has(&release.flags, "is-upgrade")
            || [
                "is-downgrade",
                "blocked-version",
                "blocked-approval",
                "is-alternate-branch",
                "unknown",
            ]
            .iter()
            .any(|flag| has(&release.flags, flag))
        {
            return Err(invalid("fwupd did not report a trusted eligible upgrade").into());
        }
        if let Some(fw_type) = self.device.component.esrt_type() {
            let entry = unique(
                observed
                    .esrt
                    .iter()
                    .filter(|entry| entry.guid == self.device.guid),
                "the qualified capsule requires a unique matching ESRT entry",
            )?;
            if entry.fw_type != fw_type || Some(entry.fw_version) != self.from.raw {
                return Err(
                    invalid("ESRT does not match the current qualified firmware version").into(),
                );
            }
        }
        Ok(())
    }

    fn check_device(&self, device: &ObservedDevice) -> Result<()> {
        let identity = &self.device;
        if device.name.as_deref() != Some(&identity.model)
            || device.plugin.as_deref() != Some(identity.component.plugin())
            || !has(&device.guid, &identity.guid)
            || !has(&device.vendor_ids, &identity.vendor_id)
            || !has(&device.protocols, identity.component.protocol())
            || identity.serial_sha256.as_ref().is_some_and(|expected| {
                device.serial.as_ref().is_none_or(|serial| {
                    serial.is_empty() || digest(serial.as_bytes()) != *expected
                })
            })
            || device.version_format.as_deref() != Some(&identity.version_format)
            || device.version.as_deref() != Some(&self.from.text)
            || device.version_raw != self.from.raw.map(u64::from)
            || !has(&device.flags, "internal")
            || !has(&device.flags, "updatable")
            || [
                "emulated",
                "historical",
                "locked",
                "unreachable",
                "updatable-hidden",
                "needs-activation",
                "needs-shutdown",
                "needs-bootloader",
                "is-bootloader",
                "wait-for-replug",
                "another-write-required",
                "will-disappear",
                "wildcard-install",
                "install-all-releases",
                "install-skip-version-check",
                "unknown",
            ]
            .iter()
            .any(|flag| has(&device.flags, flag))
            || (matches!(
                self.qualification.vendor_authentication,
                VendorAuthentication::DeviceSignature
            ) && has(&device.flags, "unsigned-payload"))
            || !device.problems.is_empty()
        {
            return Err(invalid(
                "fwupd device is inhibited or does not match the qualified physical instance",
            )
            .into());
        }
        Ok(())
    }
}

fn label(value: &str, bound: usize) -> bool {
    !value.is_empty() && value.len() <= bound && !value.chars().any(char::is_control)
}

fn name(value: &str) -> bool {
    (1..=32).contains(&value.len())
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn uuid(value: &str) -> bool {
    value.len() == 36
        && value != "00000000-0000-0000-0000-000000000000"
        && value != "ffffffff-ffff-ffff-ffff-ffffffffffff"
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

fn current(start: i64, expires: i64, now: i64) -> bool {
    start > 0 && (start..expires).contains(&now)
}

fn has(values: &[String], expected: &str) -> bool {
    values.iter().any(|value| value == expected)
}

fn unique<T>(mut items: impl Iterator<Item = T>, message: &str) -> Result<T> {
    let first = items.next().ok_or_else(|| invalid(message))?;
    if items.next().is_some() {
        return Err(invalid("firmware observation is ambiguous").into());
    }
    Ok(first)
}

fn unique_device<'a>(devices: &'a Devices, id: &str) -> Result<&'a ObservedDevice> {
    unique(
        devices
            .devices
            .iter()
            .filter(|device| device.device_id == id),
        "fwupd did not report the enrolled device instance",
    )
}

pub async fn stage(
    trusted_root: &Path,
    depot_config: &Path,
    directory: &Path,
    policy_path: &Path,
    policy_signature: &Path,
    owner_path: &Path,
    observation: &Path,
) -> Result<()> {
    let _lease = state::lock(directory)?;
    let owner = state::read(owner_path, 32)?;
    let document = state::read(policy_path, MANIFEST_BYTES)?;
    verify(
        &owner,
        &document,
        &state::read(policy_signature, 64)?,
        "invalid standing Host firmware policy signature",
    )?;
    let policy: Policy = serde_json::from_slice(&document)?;
    policy.validate(Timestamp::now().as_second())?;
    let qualification = hex::decode(&policy.qualification_key_ed25519)?;
    if owner == qualification {
        return Err(
            invalid("Host firmware owner and qualification authorities must be distinct").into(),
        );
    }
    let root = state::read(trusted_root, METADATA_BYTES)?;
    let config = state::read(depot_config, CONFIG_BYTES)?;
    if digest(&root) != policy.tuf_root_sha256 || digest(&config) != policy.depot_config_sha256 {
        return Err(invalid("firmware depot or root differs from the standing policy").into());
    }
    checkpoint(
        directory,
        "firmware-policy-checkpoint.json",
        policy.revision,
        &document,
    )?;
    let work = tempfile::Builder::new()
        .prefix(".firmware-tuf-")
        .tempdir_in(directory)?;
    let depot = Depot::from_config(&config, policy.max_archive_bytes.max(MANIFEST_BYTES))?;
    let repo = load_repository(depot, directory, root, work.path()).await?;
    if repo.root().signed.keys.values().any(|key| {
        matches!(key, Key::Ed25519 { keyval, .. } if keyval.public.as_ref() == owner || keyval.public.as_ref() == qualification)
    }) {
        return Err(invalid("TUF and Host firmware authorities must use distinct keys").into());
    }
    let stem = format!("fvca-firmware-{}", policy.channel);
    let offer_bytes = target(&repo, format!("{stem}.json"), MANIFEST_BYTES).await?;
    let signature = target(&repo, format!("{stem}.sig"), 64).await?;
    verify(
        &qualification,
        &offer_bytes,
        &signature,
        "invalid independent firmware qualification signature",
    )?;
    let offer: Offer = serde_json::from_slice(&offer_bytes)?;
    let verified_at = Timestamp::now().as_second();
    offer.require_scope(&policy, verified_at)?;
    let expires = [
        policy.expires,
        offer.expires,
        repo.root().signed.expires.as_second(),
        repo.timestamp().signed.expires.as_second(),
        repo.snapshot().signed.expires.as_second(),
        repo.targets().signed.expires.as_second(),
    ]
    .into_iter()
    .min()
    .expect("fixed list of expiry dates");
    let observation_bytes = state::read(observation, OBSERVATION_LIMIT)?;
    let observed: Observation = serde_json::from_slice(&observation_bytes)?;
    let observe = || {
        let now = Timestamp::now().as_second();
        if !(verified_at..expires).contains(&now) {
            return Err(invalid("firmware authorization expired or the clock regressed").into());
        }
        offer.require_observation(&policy, &observed, now)
    };
    checkpoint(
        directory,
        &format!("{stem}-checkpoint.json"),
        offer.sequence,
        &offer_bytes,
    )?;
    observe()?;
    let parent = directory.join("staged");
    state::staged(&parent)?;
    let approval_sha256 = digest(&offer_bytes);
    let staged = stage_archive(
        &repo,
        &parent,
        &offer,
        &offer_bytes,
        &signature,
        &approval_sha256,
        &observe,
    )
    .await?;
    let vendor_authentication = match offer.qualification.vendor_authentication {
        VendorAuthentication::DeviceSignature => "device-signature",
        VendorAuthentication::IndependentlyVerifiedVendorSignature => {
            "independently-verified-vendor-signature"
        }
    };
    println!(
        "{}",
        serde_json::to_string(&Staged {
            schema: "fvca-firmware-stage-status-v1",
            disposition: "staged",
            offer_sha256: &approval_sha256,
            archive_sha256: &offer.archive.sha256,
            observation_sha256: &digest(&observation_bytes),
            qualified_vendor_authentication: vendor_authentication,
            staged: &staged,
        })?
    );
    Ok(())
}

#[derive(Serialize)]
struct Staged<'a> {
    schema: &'static str,
    disposition: &'static str,
    offer_sha256: &'a str,
    archive_sha256: &'a str,
    observation_sha256: &'a str,
    qualified_vendor_authentication: &'static str,
    staged: &'a Path,
}

async fn stage_archive(
    repo: &Repository,
    parent: &Path,
    offer: &Offer,
    document: &[u8],
    signature: &[u8],
    approval_sha256: &str,
    observe: &dyn Fn() -> Result<()>,
) -> Result<PathBuf> {
    let target = TargetName::new(format!("fvca-firmware-{}.cab", offer.archive.sha256))?;
    if check_target(repo, &target, offer.archive.bytes, &offer.archive.sha256)?
        != offer.archive.bytes
    {
        return Err(invalid("firmware cabinet length differs from its qualification").into());
    }
    let destination = parent.join(approval_sha256);
    match fs::symlink_metadata(&destination) {
        Ok(_) => {
            state::directory(&destination)?;
            if fs::read_dir(&destination)?.count() != 3
                || state::read(&destination.join(OFFER), MANIFEST_BYTES)? != document
                || state::read(&destination.join(SIGNATURE), 64)? != signature
            {
                return Err(
                    invalid("existing firmware stage does not match the signed offer").into(),
                );
            }
            verify_member(
                state::open_regular(&destination.join(ARCHIVE))?,
                &offer.archive,
            )?;
            observe()?;
            return Ok(destination);
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    let temporary = tempfile::Builder::new()
        .prefix(".firmware-")
        .permissions(Permissions::from_mode(0o700))
        .tempdir_in(parent)?;
    let path = temporary.path();
    download(repo, &target, &path.join(ARCHIVE), offer.archive.bytes).await?;
    verify_member(state::open_regular(&path.join(ARCHIVE))?, &offer.archive)?;
    for (name, bytes) in [(OFFER, document), (SIGNATURE, signature)] {
        let mut file = output_file(&path.join(name))?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    File::open(path)?.sync_all()?;
    observe()?;
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        path,
        rustix::fs::CWD,
        &destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )?;
    File::open(parent)?.sync_all()?;
    Ok(destination)
}
