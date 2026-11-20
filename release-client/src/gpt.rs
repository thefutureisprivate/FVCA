//! Offline installation into a reviewed inactive Hypervisor GPT slot.

mod floor;
mod layout;

pub use floor::verify_floor;

use std::collections::HashSet;
use std::fs::{self, File, Permissions};
use std::io::{self, Write};
use std::os::unix::fs::{FileExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{MANIFEST_BYTES, Result, Role, Selection, install, invalid, state, valid_digest};
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

struct ReleaseEpoch<'a> {
    number: u64,
    policy: &'a str,
    auto_pcr_key: Option<&'a str>,
    require_trial: bool,
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
    let result = Command::new(program).env_clear().args(args).output()?;
    if !result.status.success() {
        return Err(io::Error::other(format!(
            "{program} refused the Hypervisor EFI loader: {}",
            String::from_utf8_lossy(&result.stderr).trim()
        ))
        .into());
    }
    Ok(())
}

fn verify_epoch(efi: &Path, expected: &ReleaseEpoch<'_>) -> Result<()> {
    let mut command = Command::new("/usr/bin/ukify");
    command.env_clear().args([
        "--config=/dev/null",
        "--json=short",
        "--section=.cmdline:text",
    ]);
    if expected.auto_pcr_key.is_some() {
        command.arg("--section=.pcrsig:text");
    }
    let result = command.arg("inspect").arg(efi).output()?;
    if !result.status.success() {
        return Err(invalid("ukify could not inspect the signed Hypervisor command line").into());
    }
    let metadata: serde_json::Value = serde_json::from_slice(&result.stdout)?;
    let cmdline = metadata[".cmdline"]["text"].as_str().ok_or_else(|| {
        invalid("expected one textual command-line section in the signed Hypervisor UKI")
    })?;
    let mut epochs = cmdline
        .split_ascii_whitespace()
        .filter(|arg| arg.split('=').next() == Some(EPOCH_ARGUMENT));
    let marker = epochs
        .next()
        .and_then(|arg| arg.split_once('='))
        .and_then(|(_, value)| value.split_once(','));
    let Some((epoch, policy)) =
        marker.filter(|_| metadata.get("_profiles").is_none() && epochs.next().is_none())
    else {
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
        verify_auto_profile(&metadata, fingerprint)?;
    }
    if expected.require_trial {
        let mut markers = cmdline
            .split_ascii_whitespace()
            .filter(|arg| arg.split('=').next() == Some(TRIAL_ARGUMENT));
        let transaction = markers
            .next()
            .and_then(|arg| arg.split_once('=').map(|(_, id)| id));
        if !transaction.is_some_and(layout::valid_uuid) || markers.next().is_some() {
            return Err(invalid(
                "inactive Hypervisor UKI requires a signed candidate trial marker",
            )
            .into());
        }
    }
    Ok(())
}

fn verify_auto_profile(uki: &serde_json::Value, fingerprint: &str) -> Result<()> {
    let invalid_policy = || invalid("Hypervisor UKI lacks the enrolled PIN-less PCR authorization");
    let raw = uki[".pcrsig"]["text"].as_str().ok_or_else(invalid_policy)?;
    if raw.len() > 16 * 1024 {
        return Err(invalid_policy().into());
    }
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
) -> Result<[u8; 32]> {
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
    verify_epoch(&efi, epoch)?;
    let signed = state::open_regular(&efi)?;
    Ok(digest(
        &signed,
        Extent {
            start: 0,
            bytes: signed.metadata()?.len(),
        },
    )?)
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

    fn matches(&self, target: &Disk, layout: &Layout<8>, index: usize) -> io::Result<bool> {
        let wanted = self.layout.regions[index].extent.bytes;
        let installed = layout.regions[index].extent;
        let payload = Extent {
            bytes: wanted,
            ..installed
        };
        let tail = Extent {
            start: payload.end(),
            bytes: installed.bytes - wanted,
        };
        Ok(digest(&target.file, payload)? == self.digests[index] && zeroed(&target.file, tail)?)
    }

    fn verify_installed(
        &self,
        disk: &Disk,
        layout: &Layout<8>,
        cert: &File,
        work: &Path,
        epoch: &ReleaseEpoch<'_>,
    ) -> Result<()> {
        self.fits(layout)?;
        let staged = loader(&self.file, self.layout.regions[0].extent, cert, work, epoch)?;
        let installed = loader(&disk.file, layout.regions[0].extent, cert, work, epoch)?;
        if installed != staged {
            return Err(invalid(
                "installed Hypervisor EFI loader differs from its approved release",
            )
            .into());
        }
        for index in 1..SLOT.len() {
            if !self.matches(disk, layout, index)? {
                return Err(invalid(
                    "installed Hypervisor payload differs from its approved release",
                )
                .into());
            }
        }
        Ok(())
    }

    fn write(&self, target: &Disk, layout: &Layout<8>, index: usize) -> io::Result<()> {
        let extent = self.layout.regions[index].extent;
        let installed = layout.regions[index].extent;
        copy(&self.file, extent, &target.file, installed.start)?;
        clear(
            &target.file,
            Extent {
                start: installed.start + extent.bytes,
                bytes: installed.bytes - extent.bytes,
            },
        )
    }
}

pub fn inspect(path: &Path, sector: u64) -> Result<()> {
    let disk = Disk::open(path, sector, false)?;
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

fn reviewed(disk: &ReviewedDisk, sector: u64, write: bool) -> Result<(Disk, Layout<8>)> {
    let device = Disk::open(&disk.path, sector, write)?;
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
    pub(crate) fn install(
        &self,
        active: (install::Slot, u64, &str),
        selected: &Selection,
        incoming: &Path,
        state_dir: &Path,
        authorize: &dyn Fn() -> Result<()>,
    ) -> Result<()> {
        let (stable, recovery) = match active.0 {
            install::Slot::A => (&self.a, &self.b),
            install::Slot::B => (&self.b, &self.a),
        };
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
        Some(standing) => {
            let bytes = state::read(&plan.boot_certificate, MANIFEST_BYTES)?;
            if hex::encode(Sha256::digest(&bytes)) != standing.site.boot_certificate_sha256 {
                return Err(invalid(
                    "Secure Boot certificate differs from standing installation policy",
                )
                .into());
            }
            let certificate = scratch.path().join("secure-boot.pem");
            fs::write(&certificate, bytes)?;
            state::open_regular(&certificate)?
        }
    };
    let authorize = || -> Result<()> {
        if let Some(standing) = &standing {
            let current = floor::read_current(&plan.epoch_policy_sha256)?;
            if current == 0 || plan.active_epoch < current || selected.epoch < current {
                return Err(
                    invalid("installed recovery or candidate is below the live TPM floor").into(),
                );
            }
            (standing.authorize)()?;
        }
        Ok(())
    };
    let auto_pcr_key = standing
        .as_ref()
        .map(|authority| authority.site.storage_pcr_key_fingerprint.as_str());
    let active_epoch = ReleaseEpoch {
        number: plan.active_epoch,
        policy: &plan.epoch_policy_sha256,
        auto_pcr_key,
        require_trial: false,
    };
    let next_epoch = ReleaseEpoch {
        number: selected.epoch,
        policy: &plan.epoch_policy_sha256,
        auto_pcr_key,
        require_trial: standing.is_some(),
    };
    let (active, active_layout) = reviewed(&plan.active, sector, false)?;
    let (inactive, inactive_layout) = reviewed(&plan.inactive, sector, true)?;
    require_distinct_disks((&active, &active_layout), (&inactive, &inactive_layout))?;
    candidate.fits(&inactive_layout)?;
    stable.verify_installed(
        &active,
        &active_layout,
        &cert,
        scratch.path(),
        &active_epoch,
    )?;
    loader(
        &candidate.file,
        candidate.layout.regions[0].extent,
        &cert,
        scratch.path(),
        &next_epoch,
    )?;

    let mut already_installed = true;
    for index in 0..SLOT.len() {
        if !candidate.matches(&inactive, &inactive_layout, index)? {
            already_installed = false;
            break;
        }
    }
    authorize()?;
    if !already_installed {
        let esp = inactive_layout.regions[0].extent;
        clear(&inactive.file, esp)?;
        flush_for_readback(&inactive.file)?;
        if !zeroed(&inactive.file, esp)? {
            return Err(invalid("inactive EFI System Partition was not cleared").into());
        }
        writeln!(
            events,
            "FVCA_HYPERVISOR_ESP_INVALIDATED {}",
            inactive_layout.id
        )?;
        events.flush()?;

        for index in 1..SLOT.len() {
            candidate.write(&inactive, &inactive_layout, index)?;
        }
        flush_for_readback(&inactive.file)?;
        for index in 1..SLOT.len() {
            if !candidate.matches(&inactive, &inactive_layout, index)? {
                return Err(invalid("inactive payload failed its post-write verification").into());
            }
        }
        authorize()?;
        let publish = (|| -> io::Result<()> {
            candidate.write(&inactive, &inactive_layout, 0)?;
            flush_for_readback(&inactive.file)?;
            if !candidate.matches(&inactive, &inactive_layout, 0)?
                || inactive_layout.fingerprint(&inactive, sector)? != plan.inactive.gpt_sha256
            {
                return Err(invalid(
                    "inactive EFI or GPT failed its post-write verification",
                ));
            }
            Ok(())
        })();
        if let Err(error) = publish {
            if let Err(cleanup) = clear(&inactive.file, esp).and_then(|()| inactive.file.sync_all())
            {
                return Err(io::Error::other(format!(
                    "inactive EFI publication failed ({error}) and clearing it failed ({cleanup})"
                ))
                .into());
            }
            return Err(error.into());
        }
    } else {
        inactive.file.sync_all()?;
    }
    writeln!(
        events,
        "FVCA_HYPERVISOR_SLOT_INSTALLED {} {} {}",
        selected.epoch, inactive_layout.id, selected.manifest_sha256
    )?;
    Ok(())
}
