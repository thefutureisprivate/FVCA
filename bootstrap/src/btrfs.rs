//! Validate the selected pool's actual kernel allocation profiles before use.

use std::fs::{self, File};
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{invalid, run, sys_block, verify_superblock};

const MOUNT: &str = "/usr/bin/mount";
const UMOUNT: &str = "/usr/bin/umount";
const OPTIONS: &str = "nodev,nosuid,noexec,subvolid=5,datacow,datasum,compress=no,skip_balance";

pub enum Pool<'a> {
    Guest(&'a Path),
    Hypervisor([&'a Path; 2]),
}

fn verify_member(source: &Path, uuid: &str, expected_count: usize) -> io::Result<()> {
    verify_superblock(source, "btrfs", uuid, None)?;
    // The primary superblock is at 64 KiB. Its little-endian num_devices field
    // is at byte 0x88 in the Btrfs on-disk superblock structure.
    let mut count = [0; 8];
    File::open(source)?.read_exact_at(&mut count, 0x10000 + 0x88)?;
    if u64::from_le_bytes(count) != expected_count as u64 {
        return Err(invalid("the Btrfs superblock device count does not match the signed layout"));
    }
    Ok(())
}

fn verify_mount(pool: &Path, target: &str, expected_devices: &[PathBuf], profiles: [&str; 3]) -> io::Result<()> {
    let root = fs::metadata(target)?;
    if root.uid() != 0 || root.gid() != 0 || root.permissions().mode() & 0o7777 != 0o700 {
        return Err(invalid("data filesystem root must be owned by root:root with mode 0700"));
    }
    let mut actual = fs::read_dir(pool.join("devices"))?
        .map(|entry| fs::canonicalize(entry?.path()))
        .collect::<io::Result<Vec<_>>>()?;
    actual.sort_unstable();
    if actual != expected_devices {
        return Err(invalid("Btrfs mounted with devices outside the signed selection"));
    }
    for (kind, profile) in ["data", "metadata", "system"].into_iter().zip(profiles) {
        let allocation = pool.join("allocation").join(kind);
        let mut selected = false;
        for entry in fs::read_dir(allocation)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                if entry.file_name() != profile || selected {
                    return Err(invalid(&format!("Btrfs {kind} allocation must use only {profile}")));
                }
                selected = true;
            }
        }
        if !selected {
            return Err(invalid(&format!("Btrfs {kind} allocation profile {profile} is missing")));
        }
    }
    Ok(())
}

pub fn mount(pool: Pool<'_>, uuid: &str, target: &str) -> io::Result<()> {
    let (sources, profiles): (&[&Path], _) = match &pool {
        Pool::Guest(device) => (std::slice::from_ref(device), ["single", "dup", "dup"]),
        Pool::Hypervisor(devices) => (devices, ["raid1", "raid1", "raid1"]),
    };
    let mut devices = Vec::new();
    for source in sources {
        verify_member(source, uuid, sources.len())?;
        devices.push(sys_block(&fs::canonicalize(source)?)?);
    }
    devices.sort_unstable();
    fs::DirBuilder::new().mode(0o700).create(target)?;
    let sysfs = Path::new("/sys/fs/btrfs").join(uuid);
    let selected = sources.iter().skip(1).map(|device| format!(",device={}", device.display())).collect::<String>();
    let label = match pool {
        Pool::Guest(_) => "",
        Pool::Hypervisor(_) => ",defcontext=system_u:object_r:fvca_host_data_t:s0",
    };

    // Btrfs can replay the tree log even on a read-only mount. Inspect profiles
    // without replay, then mount normally so legitimate pending writes recover.
    for mode in ["ro,rescue=nologreplay", "rw"] {
        run(Command::new(MOUNT).args([
            "--internal-only", "-t", "btrfs", "-o", &format!("{mode},{OPTIONS}{selected}{label}"),
        ]).arg(sources[0]).arg(target))?;
        let verified = verify_mount(&sysfs, target, &devices, profiles);
        if verified.is_err() || mode != "rw" {
            run(Command::new(UMOUNT).args(["--internal-only", target]))?;
        }
        verified?;
    }
    println!("FVCA_BTRFS_PROFILES {} {} {}", profiles[0], profiles[1], profiles[2]);
    Ok(())
}
