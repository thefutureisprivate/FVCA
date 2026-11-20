//! Offline installation into a reviewed inactive Hypervisor GPT slot.

mod floor;
mod layout;
mod uki;

pub use floor::verify_floor;

use std::collections::HashSet;
use std::fs::{self, File, Permissions};
use std::io::{self, Write};
use std::net::SocketAddr;
use std::os::unix::fs::{FileExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use fvca_trial_authorization::guest_config::Policy as GuestPolicy;
use fvca_trial_authorization::{
    KEY_ARGUMENT, PEER_PARTITIONS, Standing, WATCHDOG_ARGUMENT, host_network, key_marker,
    watchdog_seconds,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{
    MANIFEST_BYTES, Result, Role, Selection, guest_configuration, install, invalid, state,
    valid_digest,
};
use layout::{Disk, Extent, Layout, check_sector, fd_path};

// Ordered to match the slot composition. The final type holds the independent,
// mutable LUKS2 member and never participates in a payload write.
const SLOT: [&str; 7] = [
    "c12a7328-f81f-11d2-ba4b-00a0c93ec93b", // ESP
    "4f68bce3-e8cd-4db1-96e7-fbcaf984b709", // core
    "2c7357ed-ebd2-46d9-aec1-23d437ec2bf5", // core verity
    "aeb6763d-b55a-506e-8525-9f5fb6edc10c", // VM runtime
    "b67a7a00-32a8-5e7e-8281-695238dfcd45", // VM runtime verity
    "198f3f77-8128-576a-b5e1-a6065680a3c3", // Guest bundle
    "94ec41bf-b72b-519a-bca3-3ceb8b1882e5", // Guest bundle verity
];
const HOST_DISK: [&str; 8] = [
    SLOT[0],
    SLOT[1],
    SLOT[2],
    SLOT[3],
    SLOT[4],
    SLOT[5],
    SLOT[6],
    "ca7d7ccb-63ed-4c53-861c-1742536059cc",
];
const DDI: [&str; 3] = [SLOT[1], SLOT[2], "41092b05-9fc8-4523-994f-2def0408b176"];
const CHUNK: usize = 1024 * 1024;
const MAX_ESP: u64 = 4 * 1024 * 1024 * 1024;
const EPOCH_ARGUMENT: &str = "fvca.hypervisor_epoch";
const TRIAL_ARGUMENT: &str = "fvca.hypervisor_trial";

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewedDisk {
    path: PathBuf,
    gpt_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StandingSite {
    sector_size: u64,
    boot_certificate: PathBuf,
    boot_certificate_sha256: String,
    epoch_policy_sha256: String,
    storage_pcr_key_fingerprint: String,
    a: ReviewedDisk,
    b: ReviewedDisk,
}

struct StandingCheck<'a> {
    site: &'a StandingSite,
    authorize: &'a dyn Fn() -> Result<()>,
    live: Option<LiveInstall<'a>>,
}

pub(crate) struct LiveInstall<'a> {
    pub peer: [&'a str; PEER_PARTITIONS],
    pub approval: &'a Standing<'a>,
    pub trial_key: &'a [u8],
    pub guest_change: Option<&'a guest_configuration::Grant>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Review {
    schema: String,
    sector_size: u64,
    boot_certificate: PathBuf,
    epoch_policy_sha256: String,
    active_epoch: u64,
    active_manifest_sha256: String,
    active: ReviewedDisk,
    inactive: ReviewedDisk,
}

struct Artifact {
    file: File,
    layout: Layout<7>,
    digests: [[u8; 32]; 7],
}

struct WritableSlot<'a> {
    disk: &'a Disk,
    layout: &'a Layout<8>,
    partitions: Option<[File; SLOT.len()]>,
}

impl<'a> WritableSlot<'a> {
    fn claim(disk: &'a Disk, layout: &'a Layout<8>) -> Result<Self> {
        // The eighth partition contains Host data. Never open it for writing.
        let partitions = disk
            .physical
            .then(|| disk.claim_partitions(layout.regions.first_chunk().expect("payload regions")))
            .transpose()?;
        Ok(Self {
            disk,
            layout,
            partitions,
        })
    }

    fn region(&self, index: usize) -> (&File, Extent) {
        let mut extent = self.layout.regions[index].extent;
        let file = match &self.partitions {
            Some(partitions) => {
                extent.start = 0;
                &partitions[index]
            }
            None => &self.disk.file,
        };
        (file, extent)
    }

    fn flush(&self) -> io::Result<()> {
        let files = self
            .partitions
            .as_ref()
            .map_or(std::slice::from_ref(&self.disk.file), |files| {
                files.as_slice()
            });
        files.iter().try_for_each(flush_for_readback)
    }
}

struct ReleaseEpoch<'a> {
    number: u64,
    policy: &'a str,
    auto_pcr_key: Option<&'a str>,
    require_trial: bool,
    trial: Option<&'a Standing<'a>>,
    trial_key: Option<&'a [u8]>,
}

#[derive(PartialEq, Eq)]
struct VerifiedLoader {
    sha256: [u8; 32],
    guest_configuration: GuestPolicy,
    management_enrollment: Option<ManagementBinding>,
    host_network: Option<String>,
}

impl VerifiedLoader {
    fn require_host_configuration(
        &self,
        candidate: &Self,
        running: bool,
        grant: Option<&guest_configuration::Grant>,
    ) -> Result<()> {
        let stable = &self.guest_configuration;
        let next = &candidate.guest_configuration;
        if self.management_enrollment != candidate.management_enrollment {
            return Err(invalid("Host updates must preserve the management enrollment").into());
        }
        if self.host_network != candidate.host_network {
            return Err(invalid("Host updates must preserve the signed uplink profile").into());
        }
        if stable.authority != next.authority {
            return Err(invalid(
                "Host updates must preserve the enrolled Guest configuration authority",
            )
            .into());
        }
        match grant {
            Some(grant) => {
                if stable.authority != Some(grant.authority)
                    || stable.binding != grant.change.previous
                    || next.binding.as_ref() != Some(&grant.change.next)
                {
                    return Err(invalid(
                        "the signed slots differ from the authorized Guest configuration change",
                    )
                    .into());
                }
            }
            None if stable.binding != next.binding => {
                return Err(invalid("ordinary Host updates must preserve the signed Guest configuration revision and digest").into());
            }
            None => (),
        }
        if running {
            if *stable != guest_configuration::running()?.0 {
                return Err(invalid(
                    "the installed stable UKI differs from the running Guest configuration",
                )
                .into());
            }
            let args = state::read(Path::new("/proc/cmdline"), 32 * 1024)?;
            let args = std::str::from_utf8(&args)?;
            if host_network::binding(args)? != self.host_network.as_deref() {
                return Err(invalid(
                    "the installed stable UKI differs from the running Host uplink",
                )
                .into());
            }
            if fvca_trial_authorization::management_binding(args)?
                != self
                    .management_enrollment
                    .as_ref()
                    .map(|(digest, address)| (digest.as_str(), *address))
            {
                return Err(invalid(
                    "the installed stable UKI differs from the running management enrollment",
                )
                .into());
            }
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoragePcrPolicy {
    sha256: [StoragePcrSignature; 1],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoragePcrSignature {
    pcrs: [u8; 1],
    pkfp: String,
    #[serde(rename = "ref")]
    purpose: String,
    pol: String,
    sig: String,
}

fn digest(file: &File, extent: Extent) -> io::Result<[u8; 32]> {
    let mut hash = Sha256::new();
    let mut buffer = vec![0; CHUNK];
    for (offset, size) in extent.chunks(buffer.len()) {
        file.read_exact_at(&mut buffer[..size], offset)?;
        hash.update(&buffer[..size]);
    }
    Ok(hash.finalize().into())
}

fn zeroed(file: &File, extent: Extent) -> io::Result<bool> {
    let mut buffer = vec![0; CHUNK];
    for (offset, size) in extent.chunks(buffer.len()) {
        file.read_exact_at(&mut buffer[..size], offset)?;
        if buffer[..size].iter().any(|byte| *byte != 0) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn clear(file: &File, extent: Extent) -> io::Result<()> {
    let zeros = vec![0; CHUNK];
    for (offset, size) in extent.chunks(zeros.len()) {
        file.write_all_at(&zeros[..size], offset)?;
    }
    Ok(())
}

fn flush_for_readback(file: &File) -> io::Result<()> {
    file.sync_all()?;
    rustix::fs::fadvise(file, 0, None, rustix::fs::Advice::DontNeed)?;
    Ok(())
}

fn copy(source: &File, extent: Extent, target: &File, destination: u64) -> io::Result<()> {
    let mut buffer = vec![0; CHUNK];
    for (offset, size) in extent.chunks(buffer.len()) {
        source.read_exact_at(&mut buffer[..size], offset)?;
        target.write_all_at(&buffer[..size], destination + (offset - extent.start))?;
    }
    Ok(())
}

fn tool(program: &str, args: &[&Path]) -> Result<()> {
    let mut command = Command::new(program);
    command.env_clear().args(args);
    #[cfg(feature = "appliance")]
    if program == "/usr/bin/mcopy" {
        command.env("MTOOLSRC", "/usr/share/fvca/mtools.conf");
        command.env("GCONV_PATH", "/usr/lib64/fvca/fat-gconv");
    }
    let result = command.output()?;
    if !result.status.success() {
        return Err(io::Error::other(format!(
            "{program} refused the Hypervisor EFI loader: {}",
            String::from_utf8_lossy(&result.stderr).trim()
        ))
        .into());
    }
    Ok(())
}

type ManagementBinding = (String, SocketAddr);
type BootBindings = (GuestPolicy, Option<ManagementBinding>, Option<String>);

fn verify_epoch(efi: &File, expected: &ReleaseEpoch<'_>) -> Result<BootBindings> {
    let uki::Policy { cmdline, pcrsig } = uki::read(efi)?;
    let mut epochs = cmdline
        .split_ascii_whitespace()
        .filter(|arg| arg.split('=').next() == Some(EPOCH_ARGUMENT));
    let marker = epochs
        .next()
        .and_then(|arg| arg.split_once('='))
        .and_then(|(_, value)| value.split_once(','));
    let Some((epoch, policy)) = marker.filter(|_| epochs.next().is_none()) else {
        return Err(invalid(
            "expected one epoch and TPM policy in a single-profile Hypervisor UKI",
        )
        .into());
    };
    if epoch != expected.number.to_string() {
        return Err(
            invalid("signed Hypervisor UKI epoch differs from the approved release").into(),
        );
    }
    if policy != expected.policy {
        return Err(invalid(
            "signed Hypervisor UKI TPM policy differs from the reviewed enrollment",
        )
        .into());
    }
    if let Some(fingerprint) = expected.auto_pcr_key {
        verify_auto_profile(pcrsig.as_deref(), fingerprint)?;
    }
    if expected.require_trial {
        let mut markers = cmdline
            .split_ascii_whitespace()
            .filter(|arg| arg.split('=').next() == Some(TRIAL_ARGUMENT));
        let transaction = markers
            .next()
            .and_then(|arg| arg.split_once('=').map(|(_, id)| id));
        if !transaction.is_some_and(layout::valid_uuid)
            || markers.next().is_some()
            || expected.trial.is_some_and(|approval| {
                transaction != Some(approval.authorization.trial.transaction)
            })
        {
            return Err(invalid(
                "inactive Hypervisor UKI requires a signed candidate trial marker",
            )
            .into());
        }
        let mut watchdog = cmdline
            .split_ascii_whitespace()
            .filter(|arg| arg.split('=').next() == Some(WATCHDOG_ARGUMENT));
        let seconds = watchdog
            .next()
            .and_then(|arg| arg.split_once('='))
            .map(|(_, seconds)| seconds);
        if !seconds.is_some_and(|seconds| watchdog_seconds(seconds).is_ok())
            || watchdog.next().is_some()
        {
            return Err(invalid(
                "inactive Hypervisor UKI requires a signed trial watchdog deadline",
            )
            .into());
        }
    }
    if let Some(key) = expected.trial_key {
        let mut markers = cmdline
            .split_ascii_whitespace()
            .filter(|arg| arg.split('=').next() == Some(KEY_ARGUMENT));
        if markers.next() != Some(key_marker(key).as_str()) || markers.next().is_some() {
            return Err(
                invalid("Hypervisor UKI does not pin the qualified trial authority").into(),
            );
        }
    }
    Ok((
        GuestPolicy::parse(&cmdline)?,
        fvca_trial_authorization::management_binding(&cmdline)?
            .map(|(digest, address)| (digest.to_owned(), address)),
        host_network::binding(&cmdline)?.map(str::to_owned),
    ))
}

fn verify_auto_profile(pcrsig: Option<&str>, fingerprint: &str) -> Result<()> {
    let invalid_policy = || invalid("Hypervisor UKI lacks the enrolled PIN-less PCR authorization");
    let raw = pcrsig.ok_or_else(invalid_policy)?;
    let policy: StoragePcrPolicy = serde_json::from_str(raw).map_err(|_| invalid_policy())?;
    let [bank] = policy.sha256;
    if bank.pcrs != [11]
        || bank.pkfp != fingerprint
        || bank.purpose != "fvca-host-storage-auto-v1"
        || !valid_digest(&bank.pol)
        || bank.sig.is_empty()
    {
        return Err(invalid_policy().into());
    }
    Ok(())
}

fn loader(
    source: &File,
    esp: Extent,
    cert: &File,
    work: &Path,
    epoch: &ReleaseEpoch<'_>,
) -> Result<VerifiedLoader> {
    if esp.bytes > MAX_ESP {
        return Err(invalid("EFI System Partition exceeds its activation bound").into());
    }
    let scratch = tempfile::tempdir_in(work)?;
    let partition = tempfile::tempfile_in(scratch.path())?;
    copy(source, esp, &partition, 0)?;
    let efi = scratch.path().join("BOOTX64.EFI");
    tool(
        "/usr/bin/mcopy",
        &[
            Path::new("-i"),
            &fd_path(&partition),
            Path::new("::/EFI/BOOT/BOOTX64.EFI"),
            &efi,
        ],
    )?;
    tool(
        "/usr/bin/sbverify",
        &[Path::new("--cert"), &fd_path(cert), &efi],
    )?;
    let signed = state::open_regular(&efi)?;
    let (guest_configuration, management_enrollment, host_network) = verify_epoch(&signed, epoch)?;
    let bytes = signed.metadata()?.len();
    let hash = digest(&signed, Extent { start: 0, bytes })?;
    if epoch.trial.is_some_and(|trial| {
        trial.candidate_uki_bytes != bytes || trial.candidate_uki != hex::encode(hash)
    }) {
        return Err(invalid(
            "location or contents of the candidate UKI differ from the signed trial",
        )
        .into());
    }
    Ok(VerifiedLoader {
        sha256: hash,
        guest_configuration,
        management_enrollment,
        host_network,
    })
}

impl Artifact {
    fn open(directory: &Path, sector: u64) -> Result<Self> {
        let file = state::open_regular(&directory.join("boot.raw"))?;
        let layout = Layout::read(&file, file.metadata()?.len(), sector, SLOT)?;
        let mut digests = [[0; 32]; 7];
        for (expected, region) in digests.iter_mut().zip(&layout.regions) {
            *expected = digest(&file, region.extent)?;
        }
        for (member, index) in [("vm-runtime.raw", 3), ("guest-boot.raw", 5)] {
            let ddi = state::open_regular(&directory.join(member))?;
            let detached = Layout::read(&ddi, ddi.metadata()?.len(), 512, DDI)?;
            for offset in 0..2 {
                let packed = &layout.regions[index + offset];
                let independent = detached.regions[offset].extent;
                if independent.bytes != packed.extent.bytes
                    || digest(&ddi, independent)? != digests[index + offset]
                {
                    return Err(invalid("packed Hypervisor slot differs from its authorized runtime or Guest artifact").into());
                }
            }
        }
        Ok(Self {
            file,
            layout,
            digests,
        })
    }

    fn fits(&self, layout: &Layout<8>) -> Result<()> {
        if self.layout.id != layout.id
            || self.layout.regions[0].extent.bytes != layout.regions[0].extent.bytes
            || self
                .layout
                .regions
                .iter()
                .zip(&layout.regions)
                .any(|(source, dest)| {
                    source.uuid != dest.uuid || source.extent.bytes > dest.extent.bytes
                })
        {
            return Err(invalid(
                "authorized release does not fit the reviewed slot UUIDs and capacities",
            )
            .into());
        }
        Ok(())
    }

    fn require_trial_target(
        &self,
        approval: &Standing<'_>,
        stable: &Layout<8>,
        inactive: &Layout<8>,
    ) -> Result<()> {
        let authorized = &approval.authorization;
        if authorized.trial.stable.esp != stable.regions[0].uuid
            || authorized.trial.candidate.esp != inactive.regions[0].uuid
            || authorized.bytes != inactive.regions[0].extent.bytes
            || authorized.digest != hex::encode(self.digests[0])
            || !inactive.regions[1..PEER_PARTITIONS]
                .iter()
                .map(|region| region.uuid.as_str())
                .eq(approval.payloads.as_flattened().iter().copied())
        {
            return Err(invalid(
                "trial approval differs from the reviewed EFI partitions or selected ESP bytes",
            )
            .into());
        }
        Ok(())
    }

    fn matches(&self, target: &File, installed: Extent, index: usize) -> io::Result<bool> {
        let wanted = self.layout.regions[index].extent.bytes;
        let payload = Extent {
            bytes: wanted,
            ..installed
        };
        let tail = Extent {
            start: payload.end(),
            bytes: installed.bytes - wanted,
        };
        Ok(digest(target, payload)? == self.digests[index] && zeroed(target, tail)?)
    }

    fn verify_installed(
        &self,
        disk: &Disk,
        layout: &Layout<8>,
        cert: &File,
        work: &Path,
        epoch: &ReleaseEpoch<'_>,
    ) -> Result<VerifiedLoader> {
        self.fits(layout)?;
        let staged = loader(&self.file, self.layout.regions[0].extent, cert, work, epoch)?;
        let installed = loader(&disk.file, layout.regions[0].extent, cert, work, epoch)?;
        if installed != staged {
            return Err(invalid(
                "installed Hypervisor EFI loader differs from its approved release",
            )
            .into());
        }
        for (index, region) in layout.regions.iter().take(SLOT.len()).enumerate().skip(1) {
            if !self.matches(&disk.file, region.extent, index)? {
                return Err(invalid(
                    "installed Hypervisor payload differs from its approved release",
                )
                .into());
            }
        }
        Ok(installed)
    }

    fn write(&self, target: &File, installed: Extent, index: usize) -> io::Result<()> {
        let extent = self.layout.regions[index].extent;
        copy(&self.file, extent, target, installed.start)?;
        clear(
            target,
            Extent {
                start: installed.start + extent.bytes,
                bytes: installed.bytes - extent.bytes,
            },
        )
    }
}

pub fn inspect(path: &Path, sector: u64) -> Result<()> {
    let disk = Disk::open(path, sector)?;
    let layout = Layout::read(&disk.file, disk.bytes, sector, HOST_DISK)?;
    println!(
        "{}",
        serde_json::json!({
            "path": std::path::absolute(path)?,
            "gpt_sha256": layout.fingerprint(&disk, sector)?,
        })
    );
    Ok(())
}

fn reviewed(disk: &ReviewedDisk, sector: u64) -> Result<(Disk, Layout<8>)> {
    let device = Disk::open(&disk.path, sector)?;
    reviewed_layout(disk, sector, device)
}

fn reviewed_layout(disk: &ReviewedDisk, sector: u64, device: Disk) -> Result<(Disk, Layout<8>)> {
    let layout = Layout::read(&device.file, device.bytes, sector, HOST_DISK)?;
    if layout.fingerprint(&device, sector)? != disk.gpt_sha256 {
        return Err(invalid("installed GPT differs from the reviewed disk fingerprint").into());
    }
    Ok((device, layout))
}

fn require_distinct_disks(first: (&Disk, &Layout<8>), second: (&Disk, &Layout<8>)) -> Result<()> {
    let (first_disk, first_layout) = first;
    let (second_disk, second_layout) = second;
    let identities: HashSet<_> = first_layout
        .regions
        .iter()
        .chain(&second_layout.regions)
        .map(|part| &part.uuid)
        .collect();
    if first_disk.physical != second_disk.physical
        || first_layout.id == second_layout.id
        || identities.len() != 16
    {
        return Err(invalid(
            "Hypervisor disks must have distinct partition identities and the same device class",
        )
        .into());
    }
    Ok(())
}

pub fn install(plan: &Path, selected: &Selection, incoming: &Path, state_dir: &Path) -> Result<()> {
    let plan: Review = serde_json::from_slice(&state::read(plan, MANIFEST_BYTES)?)?;
    install_reviewed(
        &plan,
        selected,
        incoming,
        state_dir,
        None,
        &mut io::stdout(),
    )
}

impl StandingSite {
    fn slots(&self, active: install::Slot) -> (&ReviewedDisk, &ReviewedDisk) {
        match active {
            install::Slot::A => (&self.a, &self.b),
            install::Slot::B => (&self.b, &self.a),
        }
    }

    fn certificate(&self, scratch: &Path) -> Result<File> {
        if !self.boot_certificate.is_absolute() {
            return Err(invalid("reviewed Secure Boot certificate path must be absolute").into());
        }
        let bytes = state::read(&self.boot_certificate, MANIFEST_BYTES)?;
        if hex::encode(Sha256::digest(&bytes)) != self.boot_certificate_sha256 {
            return Err(invalid(
                "Secure Boot certificate differs from standing installation policy",
            )
            .into());
        }
        let certificate = scratch.join("secure-boot.pem");
        fs::write(&certificate, bytes)?;
        Ok(state::open_regular(&certificate)?)
    }

    fn require_trial_epochs(
        &self,
        active: u64,
        candidate: u64,
        approval: &Standing<'_>,
    ) -> Result<()> {
        if approval.stable_epoch != active
            || approval.candidate_epoch != candidate
            || approval.epoch_policy != self.epoch_policy_sha256
        {
            return Err(invalid(
                "trial approval differs from the selected releases or TPM enrollment",
            )
            .into());
        }
        Ok(())
    }

    pub(crate) fn verify_prepared(
        &self,
        active: (install::Slot, u64, &str),
        selected: &Selection,
        incoming: &Path,
        scratch: &Path,
        (approval, trial_key, guest_change): (
            &Standing<'_>,
            &[u8],
            Option<&guest_configuration::Grant>,
        ),
        running: bool,
    ) -> Result<()> {
        selected.require_update_from(active.1, active.2)?;
        self.require_trial_epochs(active.1, selected.epoch, approval)?;
        let (stable, inactive) = self.slots(active.0);
        if !stable.path.is_absolute() || !inactive.path.is_absolute() {
            return Err(invalid("reviewed Hypervisor disk paths must be absolute").into());
        }
        let sector = self.sector_size;
        let (stable_disk, stable_layout) =
            reviewed_layout(stable, sector, Disk::observe(&stable.path, sector)?)?;
        let (inactive_disk, inactive_layout) =
            reviewed_layout(inactive, sector, Disk::observe(&inactive.path, sector)?)?;
        require_distinct_disks(
            (&stable_disk, &stable_layout),
            (&inactive_disk, &inactive_layout),
        )?;
        let candidate = Artifact::open(incoming, sector)?;
        candidate.fits(&inactive_layout)?;
        candidate.require_trial_target(approval, &stable_layout, &inactive_layout)?;
        for (index, region) in inactive_layout.regions.iter().take(SLOT.len()).enumerate() {
            if !candidate.matches(&inactive_disk.file, region.extent, index)? {
                return Err(invalid(
                    "installed inactive slot differs from the prepared trial release",
                )
                .into());
            }
        }
        let cert = self.certificate(scratch)?;
        let stable_loader = loader(
            &stable_disk.file,
            stable_layout.regions[0].extent,
            &cert,
            scratch,
            &ReleaseEpoch {
                number: active.1,
                policy: &self.epoch_policy_sha256,
                auto_pcr_key: Some(&self.storage_pcr_key_fingerprint),
                require_trial: false,
                trial: None,
                trial_key: Some(trial_key),
            },
        )?;
        let candidate_loader = loader(
            &inactive_disk.file,
            inactive_layout.regions[0].extent,
            &cert,
            scratch,
            &ReleaseEpoch {
                number: selected.epoch,
                policy: &self.epoch_policy_sha256,
                auto_pcr_key: Some(&self.storage_pcr_key_fingerprint),
                require_trial: true,
                trial: Some(approval),
                trial_key: Some(trial_key),
            },
        )?;
        stable_loader.require_host_configuration(&candidate_loader, running, guest_change)?;
        self.require_floor(active.1, selected.epoch)
    }

    fn require_floor(&self, active: u64, candidate: u64) -> Result<()> {
        let current = floor::read_current(&self.epoch_policy_sha256)?;
        if current == 0 || active < current || candidate < current {
            return Err(
                invalid("installed recovery or candidate is below the live TPM floor").into(),
            );
        }
        Ok(())
    }

    pub(crate) fn install(
        &self,
        active: (install::Slot, u64, &str),
        selected: &Selection,
        incoming: &Path,
        state_dir: &Path,
        authorize: &dyn Fn() -> Result<()>,
        live: Option<LiveInstall<'_>>,
    ) -> Result<()> {
        let (stable, recovery) = self.slots(active.0);
        if !valid_digest(&self.boot_certificate_sha256)
            || !valid_digest(&self.storage_pcr_key_fingerprint)
        {
            return Err(invalid(
                "standing installation requires pinned boot and storage PCR authorities",
            )
            .into());
        }
        let plan = Review {
            schema: "fvca-hypervisor-gpt-install-v2".into(),
            sector_size: self.sector_size,
            boot_certificate: self.boot_certificate.clone(),
            epoch_policy_sha256: self.epoch_policy_sha256.clone(),
            active_epoch: active.1,
            active_manifest_sha256: active.2.into(),
            active: stable.clone(),
            inactive: recovery.clone(),
        };
        install_reviewed(
            &plan,
            selected,
            incoming,
            state_dir,
            Some(StandingCheck {
                site: self,
                authorize,
                live,
            }),
            &mut io::stderr(),
        )
    }
}

fn install_reviewed(
    plan: &Review,
    selected: &Selection,
    incoming: &Path,
    state_dir: &Path,
    standing: Option<StandingCheck<'_>>,
    events: &mut impl Write,
) -> Result<()> {
    check_sector(plan.sector_size)?;
    if selected.role != Role::Hypervisor
        || plan.schema != "fvca-hypervisor-gpt-install-v2"
        || !plan.active.path.is_absolute()
        || !plan.inactive.path.is_absolute()
        || !plan.boot_certificate.is_absolute()
        || !valid_digest(&plan.epoch_policy_sha256)
        || plan.epoch_policy_sha256.bytes().all(|byte| byte == b'0')
        || !valid_digest(&plan.active.gpt_sha256)
        || !valid_digest(&plan.inactive.gpt_sha256)
        || plan.active.gpt_sha256 == plan.inactive.gpt_sha256
    {
        return Err(invalid("GPT installation requires distinct disks and an eligible reviewed Hypervisor recovery release").into());
    }
    selected.require_update_from(plan.active_epoch, &plan.active_manifest_sha256)?;
    let sector = plan.sector_size;
    let recovery = state_dir.join("staged").join(&plan.active_manifest_sha256);
    install::verify(
        &recovery,
        Role::Hypervisor,
        plan.active_epoch,
        &plan.active_manifest_sha256,
    )?;
    let stable = Artifact::open(&recovery, sector)?;
    let candidate = Artifact::open(incoming, sector)?;
    let scratch = tempfile::Builder::new()
        .prefix(".gpt-")
        .permissions(Permissions::from_mode(0o700))
        .tempdir_in(state_dir)?;
    let cert = match &standing {
        None => state::open_regular(&plan.boot_certificate)?,
        Some(standing) => standing.site.certificate(scratch.path())?,
    };
    let authorize = || -> Result<()> {
        if let Some(standing) = &standing {
            standing
                .site
                .require_floor(plan.active_epoch, selected.epoch)?;
            (standing.authorize)()?;
        }
        Ok(())
    };
    let auto_pcr_key = standing
        .as_ref()
        .map(|authority| authority.site.storage_pcr_key_fingerprint.as_str());
    let live = standing.as_ref().and_then(|check| check.live.as_ref());
    let active_epoch = ReleaseEpoch {
        number: plan.active_epoch,
        policy: &plan.epoch_policy_sha256,
        auto_pcr_key,
        require_trial: false,
        trial: None,
        trial_key: live.map(|trial| trial.trial_key),
    };
    let next_epoch = ReleaseEpoch {
        number: selected.epoch,
        policy: &plan.epoch_policy_sha256,
        auto_pcr_key,
        require_trial: standing.is_some(),
        trial: live.map(|trial| trial.approval),
        trial_key: live.map(|trial| trial.trial_key),
    };
    let (active, active_layout) = if live.is_some() {
        reviewed_layout(
            &plan.active,
            sector,
            Disk::observe(&plan.active.path, sector)?,
        )?
    } else {
        reviewed(&plan.active, sector)?
    };
    let (inactive, inactive_layout) = reviewed_layout(
        &plan.inactive,
        sector,
        Disk::update_target(&plan.inactive.path, sector)?,
    )?;
    require_distinct_disks((&active, &active_layout), (&inactive, &inactive_layout))?;
    candidate.fits(&inactive_layout)?;
    if let Some(live) = live {
        if !active.physical
            || inactive_layout.regions[..PEER_PARTITIONS]
                .iter()
                .map(|part| part.uuid.as_str())
                .ne(live.peer)
        {
            return Err(invalid(
                "reviewed inactive NVMe partitions differ from the signed peer slot",
            )
            .into());
        }
        standing
            .as_ref()
            .expect("live installation uses standing policy")
            .site
            .require_trial_epochs(plan.active_epoch, selected.epoch, live.approval)?;
        candidate.require_trial_target(live.approval, &active_layout, &inactive_layout)?;
    }
    let stable_loader = stable.verify_installed(
        &active,
        &active_layout,
        &cert,
        scratch.path(),
        &active_epoch,
    )?;
    let candidate_loader = loader(
        &candidate.file,
        candidate.layout.regions[0].extent,
        &cert,
        scratch.path(),
        &next_epoch,
    )?;
    if standing.is_some() {
        stable_loader.require_host_configuration(
            &candidate_loader,
            live.is_some(),
            live.and_then(|item| item.guest_change),
        )?;
    }

    let target = WritableSlot::claim(&inactive, &inactive_layout)?;
    if inactive_layout.fingerprint(&inactive, sector)? != plan.inactive.gpt_sha256 {
        return Err(invalid("inactive GPT changed while claiming its partitions").into());
    }
    let mut already_installed = true;
    for index in 0..SLOT.len() {
        let (file, region) = target.region(index);
        if !candidate.matches(file, region, index)? {
            already_installed = false;
            break;
        }
    }
    authorize()?;
    if !already_installed {
        let (esp, extent) = target.region(0);
        clear(esp, extent)?;
        flush_for_readback(esp)?;
        if !zeroed(esp, extent)? {
            return Err(invalid("inactive EFI System Partition was not cleared").into());
        }
        writeln!(
            events,
            "FVCA_HYPERVISOR_ESP_INVALIDATED {}",
            inactive_layout.id
        )?;
        events.flush()?;

        for index in 1..SLOT.len() {
            let (file, region) = target.region(index);
            candidate.write(file, region, index)?;
        }
        target.flush()?;
        for index in 1..SLOT.len() {
            let (file, region) = target.region(index);
            if !candidate.matches(file, region, index)? {
                return Err(invalid("inactive payload failed its post-write verification").into());
            }
        }
        authorize()?;
        let publish = (|| -> io::Result<()> {
            candidate.write(esp, extent, 0)?;
            flush_for_readback(esp)?;
            if !candidate.matches(esp, extent, 0)?
                || inactive_layout.fingerprint(&inactive, sector)? != plan.inactive.gpt_sha256
            {
                return Err(invalid(
                    "inactive EFI or GPT failed its post-write verification",
                ));
            }
            Ok(())
        })();
        if let Err(error) = publish {
            if let Err(cleanup) = clear(esp, extent).and_then(|()| esp.sync_all()) {
                return Err(io::Error::other(format!(
                    "inactive EFI publication failed ({error}) and clearing it failed ({cleanup})"
                ))
                .into());
            }
            return Err(error.into());
        }
    } else {
        target.flush()?;
    }
    writeln!(
        events,
        "FVCA_HYPERVISOR_SLOT_INSTALLED {} {} {}",
        selected.epoch, inactive_layout.id, selected.manifest_sha256
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fvca_trial_authorization::guest_config::{Binding, Change};

    #[test]
    fn standing_updates_can_change_the_uki_while_preserving_guest_intent() -> Result<()> {
        let binding = |revision: u64, nibble: &str| Binding {
            revision,
            sha256: nibble.repeat(64),
        };
        let stable = VerifiedLoader {
            sha256: [1; 32],
            guest_configuration: GuestPolicy {
                binding: Some(binding(9, "a")),
                authority: Some([3; 32]),
            },
            management_enrollment: None,
            host_network: Some("f".repeat(64)),
        };
        let candidate = |binding, authority| VerifiedLoader {
            sha256: [2; 32],
            guest_configuration: GuestPolicy { binding, authority },
            management_enrollment: None,
            host_network: Some("f".repeat(64)),
        };
        let enrolled = Some([3; 32]);
        let unchanged = candidate(Some(binding(9, "a")), enrolled);
        stable.require_host_configuration(&unchanged, false, None)?;
        let mut changed_network = candidate(Some(binding(9, "a")), enrolled);
        changed_network.host_network = None;
        assert!(
            stable
                .require_host_configuration(&changed_network, false, None)
                .is_err()
        );
        let mut changed_enrollment = candidate(Some(binding(9, "a")), enrolled);
        changed_enrollment.management_enrollment =
            Some(("e".repeat(64), "127.0.0.1:9443".parse().unwrap()));
        assert!(
            stable
                .require_host_configuration(&changed_enrollment, false, None)
                .is_err()
        );
        for change in [
            None,
            Some(binding(8, "a")),
            Some(binding(10, "b")),
            Some(binding(9, "b")),
        ] {
            assert!(
                stable
                    .require_host_configuration(&candidate(change, enrolled), false, None)
                    .is_err()
            );
        }
        let default = candidate(None, None);
        default.require_host_configuration(&candidate(None, None), false, None)?;
        for changed_key in [None, Some([4; 32])] {
            assert!(
                stable
                    .require_host_configuration(
                        &candidate(Some(binding(9, "a")), changed_key),
                        false,
                        None
                    )
                    .is_err()
            );
        }
        assert!(
            default
                .require_host_configuration(&stable, false, None)
                .is_err()
        );
        let mut grant = guest_configuration::Grant {
            authority: [3; 32],
            change: Change {
                trial_sha256: "c".repeat(64),
                previous: Some(binding(9, "a")),
                next: binding(10, "b"),
            },
            packet: Vec::new(),
        };
        let changed = candidate(Some(binding(10, "b")), enrolled);
        stable.require_host_configuration(&changed, false, Some(&grant))?;
        assert!(
            stable
                .require_host_configuration(&unchanged, false, Some(&grant))
                .is_err()
        );
        assert!(
            stable
                .require_host_configuration(
                    &candidate(Some(binding(10, "b")), None),
                    false,
                    Some(&grant)
                )
                .is_err()
        );
        grant.change.previous = Some(binding(9, "b"));
        assert!(
            stable
                .require_host_configuration(&changed, false, Some(&grant))
                .is_err()
        );
        grant.change.previous = Some(binding(9, "a"));
        grant.authority = [4; 32];
        assert!(
            stable
                .require_host_configuration(&changed, false, Some(&grant))
                .is_err()
        );
        Ok(())
    }
}
