//! Offline installation into a reviewed inactive Hypervisor GPT slot.

mod layout;

use std::collections::HashSet;
use std::fs::{File, Permissions};
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewedDisk {
    path: PathBuf,
    gpt_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Review {
    schema: String,
    sector_size: u64,
    boot_certificate: PathBuf,
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

fn loader(source: &File, esp: Extent, cert: &File, work: &Path) -> Result<[u8; 32]> {
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

pub fn install(plan: &Path, selected: &Selection, incoming: &Path, state_dir: &Path) -> Result<()> {
    let plan: Review = serde_json::from_slice(&state::read(plan, MANIFEST_BYTES)?)?;
    check_sector(plan.sector_size)?;
    if selected.role != Role::Hypervisor
        || plan.schema != "fvca-hypervisor-gpt-install-v1"
        || !plan.active.path.is_absolute()
        || !plan.inactive.path.is_absolute()
        || !plan.boot_certificate.is_absolute()
        || !valid_digest(&plan.active_manifest_sha256)
        || !valid_digest(&plan.active.gpt_sha256)
        || !valid_digest(&plan.inactive.gpt_sha256)
        || plan.active.gpt_sha256 == plan.inactive.gpt_sha256
        || !(selected.minimum_epoch..selected.epoch).contains(&plan.active_epoch)
    {
        return Err(invalid("GPT installation requires distinct disks and an eligible reviewed Hypervisor recovery release").into());
    }
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
    let cert = state::open_regular(&plan.boot_certificate)?;
    let scratch = tempfile::Builder::new()
        .prefix(".gpt-")
        .permissions(Permissions::from_mode(0o700))
        .tempdir_in(state_dir)?;
    let stable_efi = loader(
        &stable.file,
        stable.layout.regions[0].extent,
        &cert,
        scratch.path(),
    )?;
    loader(
        &candidate.file,
        candidate.layout.regions[0].extent,
        &cert,
        scratch.path(),
    )?;

    let (active, active_layout) = reviewed(&plan.active, sector, false)?;
    let (inactive, inactive_layout) = reviewed(&plan.inactive, sector, true)?;
    let identities: HashSet<_> = active_layout
        .regions
        .iter()
        .chain(&inactive_layout.regions)
        .map(|part| &part.uuid)
        .collect();
    if active.physical != inactive.physical
        || active_layout.id == inactive_layout.id
        || identities.len() != 16
    {
        return Err(invalid(
            "Hypervisor disks must have distinct partition identities and the same device class",
        )
        .into());
    }
    stable.fits(&active_layout)?;
    candidate.fits(&inactive_layout)?;
    if loader(
        &active.file,
        active_layout.regions[0].extent,
        &cert,
        scratch.path(),
    )? != stable_efi
    {
        return Err(invalid("active recovery EFI loader differs from its approved release").into());
    }
    for index in 1..SLOT.len() {
        if !stable.matches(&active, &active_layout, index)? {
            return Err(
                invalid("active recovery payload differs from its approved release").into(),
            );
        }
    }

    let mut already_installed = true;
    for index in 0..SLOT.len() {
        if !candidate.matches(&inactive, &inactive_layout, index)? {
            already_installed = false;
            break;
        }
    }
    if !already_installed {
        let esp = inactive_layout.regions[0].extent;
        clear(&inactive.file, esp)?;
        flush_for_readback(&inactive.file)?;
        if !zeroed(&inactive.file, esp)? {
            return Err(invalid("inactive EFI System Partition was not cleared").into());
        }
        println!("FVCA_HYPERVISOR_ESP_INVALIDATED {}", inactive_layout.id);
        io::stdout().flush()?;

        for index in 1..SLOT.len() {
            candidate.write(&inactive, &inactive_layout, index)?;
        }
        flush_for_readback(&inactive.file)?;
        for index in 1..SLOT.len() {
            if !candidate.matches(&inactive, &inactive_layout, index)? {
                return Err(invalid("inactive payload failed its post-write verification").into());
            }
        }
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
    println!(
        "FVCA_HYPERVISOR_SLOT_INSTALLED {} {} {}",
        selected.epoch, inactive_layout.id, selected.manifest_sha256
    );
    Ok(())
}
