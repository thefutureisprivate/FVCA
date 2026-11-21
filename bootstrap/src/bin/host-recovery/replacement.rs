use std::ffi::CString;
use std::fs::{self, File};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, FileExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

use fvca_btrfs_boundary::{self as kernel, ReplacementState};
use fvca_initrd_bootstrap::btrfs::ReplacementMount;
use fvca_initrd_bootstrap::{btrfs, find_partition, invalid, storage_integrity, sys_block, verify_superblock};

use super::{
    HEADER, MAPPER, MOUNT, Replacement, Selection, VOLUME, backup_header, close_member,
    locate, open_member, verify_header, with_write_barrier,
};

const TARGET_MAPPER: &str = "fvca-replacement";
const TARGET_VOLUME: &str = "/dev/mapper/fvca-replacement";
const TARGET_HEADER: &str = "/run/fvca-host-recovery/replacement.header";
const SURVIVOR_PROMPT: &str = "Enter FVCA survivor recovery credential:";
const SUPERBLOCKS: [u64; 3] = [65536, 64 * 1024 * 1024, 256 * 1024 * 1024 * 1024];

fn mapped(path: &Path, partition: &Path) -> io::Result<PathBuf> {
    let volume = sys_block(&fs::canonicalize(path)?)?;
    let journal = storage_integrity::verify(&volume, partition)?;
    for device in [&volume, &journal] {
        if fs::read_to_string(device.join("ro"))? != "0\n" {
            return Err(invalid("mirror replacement mappings have unexpected write access"));
        }
    }
    Ok(volume)
}

fn bytes(device: &Path) -> io::Result<u64> {
    fs::read_to_string(device.join("size"))?.trim_end().parse::<u64>().map_err(io::Error::other)?
        .checked_mul(512).ok_or_else(|| invalid("invalid Btrfs replacement device size"))
}

fn existing_target(target: &Path, block: &Path, fsid: &str) -> io::Result<bool> {
    let status = Command::new("/usr/bin/blkid").env_clear()
        .args(["--probe", "--output", "export"]).arg(target).output()?.status;
    if status.success() {
        verify_superblock(target, "btrfs", fsid, None)?;
        return Ok(true);
    }
    if status.code() != Some(2) {
        return Err(invalid("could not establish the replacement's existing filesystem state"));
    }
    // libblkid can report no signature after a read failure. Independently
    // require authenticated zero reads at every possible Btrfs superblock.
    let target = File::open(target)?;
    let size = bytes(block)?;
    for offset in SUPERBLOCKS {
        let mut superblock = [0; 4096];
        if offset + superblock.len() as u64 <= size {
            target.read_exact_at(&mut superblock, offset)?;
            if superblock.iter().any(|&byte| byte != 0) {
                return Err(invalid("replacement is neither an empty target nor the authorized Btrfs pool"));
            }
        }
    }
    Ok(false)
}

fn btrfs_id(path: &Path) -> io::Result<u64> {
    let mut id = [0; 8];
    // dev_item.devid in the authenticated Btrfs primary superblock.
    File::open(path)?.read_exact_at(&mut id, SUPERBLOCKS[0] + 0xc9)?;
    Ok(u64::from_le_bytes(id))
}

fn require_empty_tree_log(path: &Path, block: &Path) -> io::Result<()> {
    let file = File::open(path)?;
    let size = bytes(block)?;
    for offset in SUPERBLOCKS {
        let mut fields = [0; 40];
        if offset + 4096 <= size {
            // Read magic, generation, root, chunk_root and log_root through
            // the authenticated mapping for each possible superblock.
            file.read_exact_at(&mut fields, offset + 0x40)?;
            if &fields[..8] == b"_BHRfS_M" && fields[32..] != [0; 8] {
                return Err(invalid("an interrupted mirror replacement has an unexpected pending Btrfs tree log"));
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    New,
    Resuming,
    Complete,
}

fn inspect(pool: &File, fsid: &str, plan: &Replacement<'_>, target: &Path, existing: bool) -> io::Result<Phase> {
    let devinfo = Path::new("/sys/fs/btrfs").join(fsid).join("devinfo");
    let missing = fs::read_to_string(devinfo.join(plan.missing_id.to_string()).join("missing"))?;
    let (state, writes, reads) = kernel::replacement_status(pool)?;
    let replacing = existing && matches!(state, ReplacementState::Started | ReplacementState::Suspended)
        && fs::read_to_string(devinfo.join("0/replace_target"))? == "1\n";
    let member = kernel::replacement_member(pool, fsid, plan.missing_id, replacing)?;
    if missing == "0\n" && existing {
        let path = member.path.as_ref().ok_or_else(|| invalid("completed replacement has no device path"))?;
        if sys_block(&fs::canonicalize(path)?)? != target || state != ReplacementState::Finished
            || writes != 0 || reads != 0
        {
            return Err(invalid("completed replacement does not match the authorized target and clean kernel status"));
        }
        return Ok(Phase::Complete);
    }
    if missing != "1\n" || member.path.is_some() || member.uuid != plan.missing_uuid || bytes(target)? < member.bytes {
        return Err(invalid("missing Btrfs member identity or replacement capacity differs from authorization"));
    }
    match (existing, state) {
        (false, ReplacementState::NeverStarted | ReplacementState::Canceled | ReplacementState::Finished) => Ok(Phase::New),
        (true, ReplacementState::Started | ReplacementState::Suspended)
            if replacing && writes == 0 && reads == 0 =>
        {
            Ok(Phase::Resuming)
        }
        _ => Err(invalid("Btrfs replacement state does not match the authorized target")),
    }
}

fn verify_and_scrub(pool: &File, fsid: &str) -> io::Result<()> {
    kernel::repair_single_allocations(pool)?;
    for id in kernel::scrub_members(pool, fsid, true)? {
        let limit = btrfs::scrub_limit(fsid, id);
        fs::write(&limit, format!("{}\n", btrfs::SCRUB_LIMIT))?;
        if fs::read_to_string(&limit)?.trim_end().parse::<u64>().ok() != Some(btrfs::SCRUB_LIMIT) {
            return Err(invalid("kernel did not retain the recovery scrub limit"));
        }
        let (progress, result) = kernel::scrub(pool, id);
        println!("FVCA_HOST_REPLACEMENT_SCRUB {id} {} {} {} {} {} {}",
                 progress.data_bytes, progress.metadata_bytes, progress.corrected_errors,
                 progress.uncorrectable_errors, progress.allocation_errors, progress.no_checksum_blocks);
        result?;
        if progress.uncorrectable_errors != 0 || progress.allocation_errors != 0 || progress.no_checksum_blocks != 0 {
            return Err(invalid("Btrfs replacement scrub did not verify all checksummed data"));
        }
    }
    kernel::require_raid1_profiles(pool)?;
    kernel::sync(pool)
}

fn repair(
    selection: &Selection<'_>, plan: &Replacement<'_>, survivor: &Path, target: &Path,
    source_block: &Path, target_block: &Path, existing: bool,
) -> io::Result<()> {
    let fsid = selection.filesystem;
    let devices = [source_block.to_owned(), target_block.to_owned()];
    let initial = if existing { &devices[..] } else { &devices[..1] };
    let companion = existing.then_some(target);
    fs::DirBuilder::new().mode(0o700).create(MOUNT)?;
    let finish = |pool: &File| {
        btrfs::verify_replacement_mount(fsid, MOUNT, &devices)?;
        if inspect(pool, fsid, plan, target_block, true)? != Phase::Complete {
            return Err(invalid("Btrfs replacement did not complete"));
        }
        verify_and_scrub(pool, fsid)
    };
    if existing && btrfs_id(target)? == 0 {
        require_empty_tree_log(survivor, source_block)?;
        require_empty_tree_log(target, target_block)?;
        // Keep the interrupted replacement mounted across the verified
        // transition. Unmounting it read-only can unbalance the kernel's
        // block freeze accounting, and the active copy needs its same target.
        return btrfs::with_replacement_mount(survivor, companion, MOUNT, ReplacementMount::Resume, |pool| {
            btrfs::verify_replacement_mount(fsid, MOUNT, initial)?;
            if inspect(pool, fsid, plan, target_block, true)? != Phase::Resuming {
                return Err(invalid("an interrupted copy could not be identified"));
            }
            selection.verify_time()?;
            println!("FVCA_HOST_MIRROR_COPY_RESUME {}", plan.missing_id);
            btrfs::resume_replacement_mount(MOUNT)?;
            while kernel::replacement_status(pool)?.0 == ReplacementState::Started {
                thread::sleep(Duration::from_secs(1));
            }
            finish(pool)
        });
    }
    let phase = btrfs::with_replacement_mount(survivor, companion, MOUNT, ReplacementMount::Inspect, |pool| {
        btrfs::verify_replacement_mount(fsid, MOUNT, initial)?;
        inspect(pool, fsid, plan, target_block, existing)
    })?;
    selection.verify_time()?;
    btrfs::with_replacement_mount(survivor, companion, MOUNT, ReplacementMount::Write, |pool| {
        btrfs::verify_replacement_mount(fsid, MOUNT, initial)?;
        let before = inspect(pool, fsid, plan, target_block, existing)?;
        if phase == Phase::New && before == Phase::New {
            let target = CString::new(target.as_os_str().as_encoded_bytes()).map_err(io::Error::other)?;
            println!("FVCA_HOST_MIRROR_COPY_BEGIN {}", plan.missing_id);
            kernel::start_missing_replacement(pool, plan.missing_id, &target)?;
        } else if phase != Phase::Complete || before != Phase::Complete {
            return Err(invalid("Btrfs replacement changed unexpectedly during the maintenance mount"));
        }
        finish(pool)
    })
}

pub(super) fn replace(
    selection: &Selection<'_>, plan: &Replacement<'_>, source: &Path, pinned: &Path, partition: &Path,
) -> io::Result<()> {
    if find_partition(plan.failed_partition)?.is_some() {
        return Err(invalid("the failed member must be absent during replacement"));
    }
    let target = fs::canonicalize(locate(plan.partition)?)?;
    let target_partition = sys_block(&target)?;
    if !target_partition.join("partition").is_file() || target_partition.parent() == partition.parent() {
        return Err(invalid("mirror replacement requires an authorized partition on a separate disk"));
    }
    let target_disk = File::open(&target)?;
    let target_pinned = PathBuf::from(format!("/proc/{}/fd/{}", std::process::id(), target_disk.as_raw_fd()));
    with_write_barrier(&target, &target_pinned, &target_partition, |block, _| {
        backup_header(block, plan.luks, TARGET_HEADER)?;
        verify_header(TARGET_HEADER, plan.luks, plan.header_digest)
    })?;
    let survivor = Path::new(VOLUME);
    with_write_barrier(source, pinned, partition, |block, _| {
        backup_header(block, selection.luks, HEADER)?;
        verify_header(HEADER, selection.luks, selection.header_digest)
    })?;
    // Only this signed write operation permits replay of the two selected
    // dm-integrity journals. The regular assessment still blocks those writes.
    selection.verify_time()?;
    open_member(&target_pinned, TARGET_MAPPER, TARGET_HEADER, plan.key_slot, false,
                "Enter FVCA replacement recovery credential:")?;
    let target = Path::new(TARGET_VOLUME);
    let result = (|| {
        let target_block = mapped(target, &target_partition)?;
        let existing = existing_target(target, &target_block, selection.filesystem)?;
        selection.verify_time()?;
        open_member(pinned, MAPPER, HEADER, selection.key_slot, false, SURVIVOR_PROMPT)?;
        let result = (|| {
            let source_block = mapped(survivor, partition)?;
            btrfs::verify_member(survivor, selection.filesystem, 2)?;
            repair(selection, plan, survivor, target, &source_block, &target_block, existing)
        })();
        close_member(MAPPER)?;
        result
    })();
    close_member(TARGET_MAPPER)?;
    result?;
    fs::remove_file(HEADER)?;
    fs::remove_file(TARGET_HEADER)?;
    println!("FVCA_HOST_MIRROR_REPLACED {} {} raid1", selection.filesystem, plan.missing_id);
    Ok(())
}
