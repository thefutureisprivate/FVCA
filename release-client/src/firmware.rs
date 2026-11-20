//! Authenticate an exact Host firmware offer and stage its cabinet for qualification.

mod activation;
mod boot;
mod bus;
mod capsule;
mod live;
mod qualification;
mod result;
mod transition;

use std::fs::{self, File, Permissions};
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use fvca_trial_authorization::firmware::{self as firmware_fence, STATE_DIRECTORY as ENROLLMENT};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use tough::schema::key::Key;
use tough::{Repository, TargetName};

use crate::channel::{Window, checkpoint, digest, save, target, verify};
use crate::depot::{CONFIG_BYTES, Depot, EnrolledDepot, METADATA_BYTES};
use crate::{
    MANIFEST_BYTES, Member, Result, Role, check_target, download, handoff, invalid,
    load_repository, output_file, state, valid_digest, verify_member,
};

const ARCHIVE_LIMIT: u64 = 256 * 1024 * 1024;
const CATALOG_LIMIT: u64 = 32 * 1024 * 1024;
const JCAT_LIMIT: u64 = 1024 * 1024;
const OBSERVATION_LIMIT: u64 = 1024 * 1024;
const OBSERVATION_AGE: i64 = 300;
const OFFER: &str = "offer.json";
const SIGNATURE: &str = "offer.sig";
const ARCHIVE: &str = "firmware.cab";
const STATUS: &str = "firmware-update-status.json";
const OBSERVATION_SCHEMA: &str = "fvca-firmware-observation-v2";
const HEAD_SCHEMA: &str = "fvca-firmware-channel-v1";

#[derive(Deserialize, Eq, PartialEq, Serialize)]
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

    fn matches_device(&self, device: &ObservedDevice) -> bool {
        device.device_id == self.device_id
            && device.name.as_deref() == Some(&self.model)
            && device.plugin.as_deref() == Some(self.component.plugin())
            && has(&device.guid, &self.guid)
            && has(&device.vendor_ids, &self.vendor_id)
            && has(&device.protocols, self.component.protocol())
            && self.serial_sha256.as_ref().is_none_or(|expected| {
                device.serial.as_ref().is_some_and(|serial| {
                    !serial.is_empty() && digest(serial.as_bytes()) == *expected
                })
            })
            && device.version_format.as_deref() == Some(&self.version_format)
            && has(&device.flags, "internal")
            && ![
                "emulated",
                "historical",
                "unreachable",
                "is-bootloader",
                "unknown",
            ]
            .iter()
            .any(|flag| has(&device.flags, flag))
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
    #[serde(default)]
    maintenance: Window,
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
        self.maintenance.timezone()?;
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
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

#[derive(Deserialize, Serialize)]
struct Devices {
    #[serde(rename = "Devices")]
    devices: Vec<ObservedDevice>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Esrt {
    guid: String,
    fw_type: u8,
    fw_version: u32,
    lowest_supported_fw_version: u32,
    capsule_flags: u32,
    last_attempt_version: u32,
    last_attempt_status: u32,
}

#[derive(Clone, Default, Deserialize, Serialize)]
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

#[derive(Clone, Default, Deserialize, Serialize)]
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

#[derive(Deserialize, Eq, PartialEq, Serialize)]
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

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
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
struct Catalog {
    metadata: Member,
    signature: Member,
}

impl Catalog {
    fn valid(&self) -> bool {
        [
            (&self.metadata, CATALOG_LIMIT),
            (&self.signature, JCAT_LIMIT),
        ]
        .into_iter()
        .all(|(member, limit)| (1..=limit).contains(&member.bytes) && valid_digest(&member.sha256))
    }

    fn identity(&self) -> String {
        format!("{}:{}", self.metadata.sha256, self.signature.sha256)
    }

    async fn download(&self, repo: &Repository) -> Result<[Vec<u8>; 2]> {
        let mut payloads = [Vec::new(), Vec::new()];
        for (bytes, (member, extension)) in payloads
            .iter_mut()
            .zip([(&self.metadata, "bin"), (&self.signature, "jcat")])
        {
            let name = format!("fvca-firmware-catalog-{}.{}", member.sha256, extension);
            if check_target(repo, &TargetName::new(&name)?, member.bytes, &member.sha256)?
                != member.bytes
            {
                return Err(invalid(
                    "firmware catalog target length differs from its signed offer",
                )
                .into());
            }
            *bytes = target(repo, name, member.bytes).await?;
        }
        Ok(payloads)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Head {
    schema: String,
    role: Role,
    channel: String,
    sequence: u64,
    valid_from: i64,
    expires: i64,
    system_uuid: String,
    fwupd_version: String,
    #[serde(deserialize_with = "Deserialize::deserialize")]
    offer: Option<Offer>,
}

impl Head {
    fn require_scope(&self, policy: &Policy, now: i64) -> Result<()> {
        if self.schema != HEAD_SCHEMA
            || self.role != Role::Hypervisor
            || self.channel != policy.channel
            || self.sequence == 0
            || !current(self.valid_from, self.expires, now)
            || self.expires - self.valid_from > 7 * 86_400
            || self.system_uuid != policy.platform.system_uuid
            || self.fwupd_version != policy.fwupd_version
        {
            return Err(invalid("firmware channel is outside the signed Host policy").into());
        }
        if let Some(offer) = &self.offer {
            offer.require_scope(policy)?;
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Offer {
    device: DeviceIdentity,
    remote: String,
    epoch: u64,
    from: Version,
    to: Version,
    archive: Member,
    catalog: Catalog,
    payload_sha256: String,
    qualification: Qualification,
}

impl Offer {
    fn valid_transition(&self) -> bool {
        let format = &self.device.version_format;
        self.from.matches_format(format)
            && self.to.matches_format(format)
            && self.from.text != self.to.text
            && match self.device.component.esrt_type() {
                Some(_) => {
                    matches!((self.from.raw, self.to.raw), (Some(from), Some(to)) if from < to)
                }
                None => self.from.raw.is_none() && self.to.raw.is_none(),
            }
    }

    fn require_scope(&self, policy: &Policy) -> Result<()> {
        if !policy.allowed_devices.contains(&self.device)
            || !policy.allowed_remotes.contains(&self.remote)
            || self.epoch < policy.minimum_epoch
            || !(1..=policy.max_archive_bytes).contains(&self.archive.bytes)
            || !valid_digest(&self.archive.sha256)
            || !self.catalog.valid()
            || !valid_digest(&self.payload_sha256)
        {
            return Err(invalid("firmware offer is outside the signed Host policy").into());
        }
        if !self.valid_transition() {
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

    fn require_observation<'a>(
        &self,
        policy: &Policy,
        observed: &'a Observation,
        now: i64,
    ) -> Result<Option<&'a Esrt>> {
        if observed.schema != OBSERVATION_SCHEMA
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
            return Ok(Some(entry));
        }
        Ok(None)
    }

    fn check_device(&self, device: &ObservedDevice) -> Result<()> {
        if !self.device.matches_device(device)
            || device.version.as_deref() != Some(&self.from.text)
            || device.version_raw != self.from.raw.map(u64::from)
            || !has(&device.flags, "updatable")
            || [
                "locked",
                "updatable-hidden",
                "needs-activation",
                "needs-shutdown",
                "needs-bootloader",
                "wait-for-replug",
                "another-write-required",
                "will-disappear",
                "wildcard-install",
                "install-all-releases",
                "install-skip-version-check",
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

fn boot_id() -> Result<String> {
    let bytes = state::read(Path::new("/proc/sys/kernel/random/boot_id"), 37)?;
    let id = std::str::from_utf8(&bytes)?
        .strip_suffix('\n')
        .filter(|id| uuid(id))
        .ok_or_else(|| invalid("invalid Linux boot identifier"))?;
    Ok(id.to_owned())
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

pub enum ObservationSource<'a> {
    File(&'a Path),
    Live,
    Scheduled(&'a EnrolledDepot, &'a File),
}

enum SnapshotSource {
    File(Box<Observation>, String),
    Live(live::Session),
}

pub struct Intake<'a> {
    pub trusted_root: &'a Path,
    pub depot_config: &'a Path,
    pub directory: &'a Path,
    pub policy: &'a Path,
    pub signature: &'a Path,
    pub owner: &'a Path,
}

pub async fn scheduled() -> Result<()> {
    let boot = Path::new("/run/fvca");
    if boot.join("boot-trial-started").try_exists()? {
        return Err(invalid("firmware scheduling requires a stable Hypervisor boot").into());
    }
    let directory = boot.join("host-data").join(ENROLLMENT);
    let pool_directory = handoff::require_pool_directory(&directory)?;
    let _lease = state::lock(&directory)?;
    if let Some((activation, evidence)) = activation::recover(&directory, &pool_directory)? {
        let status = Status {
            schema: "fvca-firmware-discovery-status-v1",
            disposition: activation.disposition(),
            checked_at: Timestamp::now().as_second(),
            freshness: Freshness::default(),
            staged: None,
            activation: Some(activation),
            recovery_evidence: Some(evidence),
        };
        save(&directory, STATUS, &status)?;
        println!("{}", serde_json::to_string(&status)?);
        return Ok(());
    }
    let depot = EnrolledDepot::load(boot, ENROLLMENT)?;
    stage_locked(
        Intake {
            trusted_root: &directory.join("trusted-root.json"),
            depot_config: &directory.join("depot.json"),
            directory: &directory,
            policy: &directory.join("policy.json"),
            signature: &directory.join("policy.sig"),
            owner: &boot.join("firmware-update-owner"),
        },
        ObservationSource::Scheduled(&depot, &pool_directory),
    )
    .await
}

#[derive(Default, Deserialize, Serialize)]
struct Freshness {
    channel: Option<String>,
    last_refresh: Option<i64>,
    fresh_until: Option<i64>,
    channel_sequence: Option<u64>,
}

#[derive(Serialize)]
struct Status {
    schema: &'static str,
    disposition: &'static str,
    checked_at: i64,
    #[serde(flatten)]
    freshness: Freshness,
    #[serde(flatten)]
    staged: Option<Staged>,
    #[serde(skip_serializing_if = "Option::is_none")]
    activation: Option<activation::Activation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recovery_evidence: Option<result::Evidence>,
}

pub async fn stage(inputs: Intake<'_>, source: ObservationSource<'_>) -> Result<()> {
    let _lease = state::lock(inputs.directory)?;
    firmware_fence::require_idle()?;
    stage_locked(inputs, source).await
}

async fn stage_locked(inputs: Intake<'_>, source: ObservationSource<'_>) -> Result<()> {
    let directory = inputs.directory;
    let scheduled = matches!(source, ObservationSource::Scheduled(..));
    let freshness = if scheduled {
        match state::read(&directory.join(STATUS), MANIFEST_BYTES) {
            Ok(previous) => serde_json::from_slice(&previous)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Freshness::default(),
            Err(error) => return Err(error.into()),
        }
    } else {
        Freshness::default()
    };
    let mut status = Status {
        schema: "fvca-firmware-discovery-status-v1",
        disposition: "checking",
        checked_at: Timestamp::now().as_second(),
        freshness,
        staged: None,
        activation: None,
        recovery_evidence: None,
    };
    if scheduled {
        save(directory, STATUS, &status)?;
    }
    let result = refresh(inputs, source, &mut status.freshness)
        .await
        .map(|staged| {
            status.disposition = if staged.is_some() {
                "staged"
            } else {
                "no-offer"
            };
            status.staged = staged;
        });
    if result.is_err() {
        status.disposition = "blocked";
    }
    if scheduled {
        save(directory, STATUS, &status)?;
    }
    if scheduled || result.is_ok() {
        println!("{}", serde_json::to_string(&status)?);
    }
    result
}

async fn refresh(
    inputs: Intake<'_>,
    source: ObservationSource<'_>,
    freshness: &mut Freshness,
) -> Result<Option<Staged>> {
    let directory = inputs.directory;
    let scheduled = match source {
        ObservationSource::Scheduled(depot, _) => Some((depot, ENROLLMENT)),
        _ => None,
    };
    let owner = state::read(inputs.owner, 32)?;
    let document = state::read(inputs.policy, MANIFEST_BYTES)?;
    verify(
        &owner,
        &document,
        &state::read(inputs.signature, 64)?,
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
    let root = state::read(inputs.trusted_root, METADATA_BYTES)?;
    let config = state::read(inputs.depot_config, CONFIG_BYTES)?;
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
        .tempdir()?;
    let depot = Depot::with_scope(
        &config,
        policy.max_archive_bytes.max(CATALOG_LIMIT),
        scheduled,
    )?;
    if !matches!(source, ObservationSource::File(_)) {
        live::require_platform(&policy)?;
    }
    let repo = load_repository(depot, directory, root, work.path()).await?;
    if repo.root().signed.keys.values().any(|key| {
        matches!(key, Key::Ed25519 { keyval, .. } if keyval.public.as_ref() == owner || keyval.public.as_ref() == qualification)
    }) {
        return Err(invalid("TUF and Host firmware authorities must use distinct keys").into());
    }
    let stem = format!("fvca-firmware-{}", policy.channel);
    let head_bytes = target(&repo, format!("{stem}.json"), MANIFEST_BYTES).await?;
    let signature = target(&repo, format!("{stem}.sig"), 64).await?;
    verify(
        &qualification,
        &head_bytes,
        &signature,
        "invalid independent firmware qualification signature",
    )?;
    let head: Head = serde_json::from_slice(&head_bytes)?;
    let verified_at = Timestamp::now().as_second();
    head.require_scope(&policy, verified_at)?;
    let expires = [
        policy.expires,
        head.expires,
        repo.root().signed.expires.as_second(),
        repo.timestamp().signed.expires.as_second(),
        repo.snapshot().signed.expires.as_second(),
        repo.targets().signed.expires.as_second(),
    ]
    .into_iter()
    .min()
    .expect("fixed list of expiry dates");
    let require_current = || {
        let now = Timestamp::now().as_second();
        if !(verified_at..expires).contains(&now) {
            return Err(invalid(
                "firmware authorization expired or the clock regressed",
            ));
        }
        Ok(now)
    };
    require_current()?;
    checkpoint(
        directory,
        &format!("{stem}-checkpoint.json"),
        head.sequence,
        &head_bytes,
    )?;
    *freshness = Freshness {
        channel: Some(head.channel.clone()),
        last_refresh: Some(verified_at),
        fresh_until: Some(expires),
        channel_sequence: Some(head.sequence),
    };
    let approval_sha256 = digest(&head_bytes);
    let parent = directory.join("staged");
    state::staged(&parent)?;
    let keep = head.offer.as_ref().map(|_| approval_sha256.as_str());
    require_current()?;
    retire_stages(&parent, keep, scheduled.is_some())?;
    let Some(offer) = head.offer.as_ref() else {
        require_current()?;
        return Ok(None);
    };
    let (transition_bytes, transition) = transition::download(&repo, &head, offer).await?;
    let qualified = qualification::download(&repo, offer).await?;
    let payloads = offer.catalog.download(&repo).await?;
    require_current()?;
    let snapshot = match source {
        ObservationSource::File(path) => {
            let bytes = state::read(path, OBSERVATION_LIMIT)?;
            SnapshotSource::File(serde_json::from_slice(&bytes)?, digest(&bytes))
        }
        ObservationSource::Live | ObservationSource::Scheduled(..) => {
            SnapshotSource::Live(live::Session::open(&policy, offer, &payloads)?)
        }
    };
    drop(payloads);
    let observe = |cabinet| match &snapshot {
        SnapshotSource::File(observed, sha256) => {
            offer.require_observation(&policy, observed, require_current()?)?;
            Ok(AdmittedObservation {
                sha256: sha256.clone(),
                esrt: None,
                cabinet,
                requires_ac: false,
            })
        }
        SnapshotSource::Live(live) => {
            let observed = live.read(&offer.device)?;
            let esrt = offer.require_observation(&policy, &observed, require_current()?)?;
            let device = unique_device(&observed.devices, &offer.device.device_id)?;
            Ok(AdmittedObservation {
                sha256: digest(&serde_json::to_vec(&observed)?),
                esrt: esrt.cloned(),
                cabinet,
                requires_ac: has(&device.flags, "require-ac"),
            })
        }
    };
    observe(None)?;
    let check_cabinet = |path: &Path| {
        require_current()?;
        let file = state::open_regular(path)?;
        let cabinet = match &snapshot {
            SnapshotSource::Live(live) => Some(live.verify_cabinet(file, offer)?),
            SnapshotSource::File(..) => {
                verify_member(file, &offer.archive)?;
                None
            }
        };
        observe(cabinet)
    };
    let mut records = vec![
        (OFFER, head_bytes.as_slice()),
        (SIGNATURE, signature.as_slice()),
        (transition::FILE, transition_bytes.as_slice()),
    ];
    records.extend(
        qualification::FILES
            .into_iter()
            .zip(qualified.records.iter().map(Vec::as_slice)),
    );
    let (staged, observed) = stage_archive(
        &repo,
        &parent,
        offer,
        &records,
        &approval_sha256,
        &check_cabinet,
    )
    .await?;
    let capsule_delivery = if scheduled.is_some() {
        observed
            .esrt
            .zip(offer.to.raw)
            .zip(observed.cabinet)
            .map(|((esrt, to), cabinet)| capsule::inspect(esrt, to, cabinet))
    } else {
        None
    };
    let boot_transition = match source {
        ObservationSource::Scheduled(_, pool) => {
            Some(transition::preflight(pool, &transition.before))
        }
        _ => None,
    };
    let now = Timestamp::from_second(require_current()?)?;
    let operational_preflight = boot_transition
        .as_ref()
        .map(|boot| {
            qualified.reboot.preflight(
                boot,
                capsule_delivery.as_ref(),
                observed.requires_ac,
                &policy.maintenance,
                now,
            )
        })
        .transpose()?;
    require_current()?;
    Ok(Some(Staged {
        offer_sha256: approval_sha256,
        archive_sha256: offer.archive.sha256.clone(),
        verified_payload_sha256: observed.cabinet.map(|_| offer.payload_sha256.clone()),
        verified_payload_bytes: observed.cabinet.map(|cabinet| cabinet.bytes),
        observation_sha256: observed.sha256,
        capsule_delivery,
        transition_evidence_sha256: offer.qualification.transition_evidence_sha256.clone(),
        boot_transition,
        qualified_vendor_authentication: offer.qualification.vendor_authentication,
        urgency: qualified.reboot.urgency,
        operational_preflight,
        staged,
    }))
}

struct AdmittedObservation {
    sha256: String,
    esrt: Option<Esrt>,
    cabinet: Option<live::VerifiedCabinet>,
    requires_ac: bool,
}

#[derive(Serialize)]
struct Staged {
    offer_sha256: String,
    archive_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified_payload_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified_payload_bytes: Option<u64>,
    observation_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    capsule_delivery: Option<capsule::Delivery>,
    transition_evidence_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    boot_transition: Option<transition::Status>,
    qualified_vendor_authentication: VendorAuthentication,
    urgency: qualification::Urgency,
    #[serde(skip_serializing_if = "Option::is_none")]
    operational_preflight: Option<qualification::Status>,
    staged: PathBuf,
}

fn retire_stages(parent: &Path, retain: Option<&str>, scheduled: bool) -> Result<()> {
    if scheduled {
        handoff::require_pool_directory(parent)?;
    }
    let mut removed = false;
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| invalid("invalid firmware staging name"))?;
        if !(valid_digest(name) || name.starts_with(".firmware-")) {
            return Err(invalid("unrecognized firmware staging directory").into());
        }
        let path = entry.path();
        if scheduled {
            handoff::require_pool_directory(&path)?;
        } else {
            state::directory(&path)?;
        }
        if retain == Some(name) {
            continue;
        }
        let files = fs::read_dir(&path)?.collect::<io::Result<Vec<_>>>()?;
        for file in &files {
            let name = file.file_name();
            let recognized = name.to_str().is_some_and(|name| {
                matches!(name, ARCHIVE | OFFER | SIGNATURE | transition::FILE)
                    || qualification::FILES.contains(&name)
            });
            if !recognized || !file.file_type()?.is_file() {
                return Err(invalid("unrecognized firmware staging file").into());
            }
        }
        for file in files {
            fs::remove_file(file.path())?;
        }
        fs::remove_dir(path)?;
        removed = true;
    }
    if removed {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

async fn stage_archive(
    repo: &Repository,
    parent: &Path,
    offer: &Offer,
    records: &[(&str, &[u8])],
    approval_sha256: &str,
    check_cabinet: &dyn Fn(&Path) -> Result<AdmittedObservation>,
) -> Result<(PathBuf, AdmittedObservation)> {
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
            if fs::read_dir(&destination)?.count() != records.len() + 1 {
                return Err(
                    invalid("existing firmware stage does not match the signed offer").into(),
                );
            }
            for &(name, bytes) in records {
                if state::read(&destination.join(name), bytes.len() as u64)? != bytes {
                    return Err(
                        invalid("existing firmware stage does not match the signed offer").into(),
                    );
                }
            }
            let observation = check_cabinet(&destination.join(ARCHIVE))?;
            return Ok((destination, observation));
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
    for &(name, bytes) in records {
        let mut file = output_file(&path.join(name))?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    File::open(path)?.sync_all()?;
    let observed = check_cabinet(&path.join(ARCHIVE))?;
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        path,
        rustix::fs::CWD,
        &destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )?;
    File::open(parent)?.sync_all()?;
    Ok((destination, observed))
}
