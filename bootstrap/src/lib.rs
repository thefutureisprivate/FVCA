#![forbid(unsafe_code)]

use std::fs::{self, File};
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub fn find_partition(uuid: &str) -> io::Result<Option<PathBuf>> {
    let output = Command::new("/usr/bin/blkid")
        .env_clear()
        .args(["-c", "/dev/null", "-t", &format!("PARTUUID={uuid}"), "-o", "device"])
        .stderr(Stdio::inherit())
        .output()?;
    if output.status.code() == Some(2) {
        return Ok(None);
    }
    if !output.status.success() {
        return Err(io::Error::other(format!("blkid exited with {}", output.status)));
    }
    let list = std::str::from_utf8(&output.stdout).map_err(|_| invalid("invalid partition list"))?;
    let mut paths = list.lines();
    let path = paths.next().ok_or_else(|| invalid("empty partition list"))?;
    if paths.next().is_some() {
        return Err(invalid("more than one device has the authorized partition UUID"));
    }
    let path = PathBuf::from(path);
    if !path.starts_with("/dev") || !fs::metadata(&path)?.file_type().is_block_device() {
        return Err(invalid("authorized partition is not a block device"));
    }
    Ok(Some(path))
}

pub fn run(command: &mut Command) -> io::Result<()> {
    let status = command.env_clear().status()?;
    if !status.success() {
        return Err(io::Error::other(format!("{:?} exited with {status}", command.get_program())));
    }
    Ok(())
}

pub fn sys_block(path: &Path) -> io::Result<PathBuf> {
    let name = path.file_name().ok_or_else(|| invalid("block device has no name"))?;
    fs::canonicalize(Path::new("/sys/class/block").join(name))
}

pub fn verify_superblock(path: &Path, kind: &str, uuid: &str, version: Option<&str>) -> io::Result<()> {
    let result = Command::new("/usr/bin/blkid").env_clear()
        .args(["--probe", "--output", "export"]).arg(path).output()?;
    if !result.status.success() {
        return Err(invalid("unable to probe the authorized storage superblock"));
    }
    let fields = std::str::from_utf8(&result.stdout).map_err(|_| invalid("invalid blkid output"))?;
    for (key, expected) in [("TYPE", Some(kind)), ("UUID", Some(uuid)), ("VERSION", version)] {
        if let Some(expected) = expected {
            let mut values = fields.lines().filter_map(|line| {
                let (field, value) = line.split_once('=')?;
                (field == key).then_some(value)
            });
            if values.next() != Some(expected) || values.next().is_some() {
                return Err(invalid("storage superblock does not match the signed selection"));
            }
        }
    }
    Ok(())
}

fn verify_btrfs_mount(source: &Path, uuid: &str, target: &str) -> io::Result<()> {
    let root = fs::metadata(target)?;
    if root.uid() != 0 || root.gid() != 0 || root.permissions().mode() & 0o7777 != 0o700 {
        return Err(invalid("data filesystem root must be owned by root:root with mode 0700"));
    }
    let expected = sys_block(&fs::canonicalize(source)?)?;
    let mut devices = fs::read_dir(format!("/sys/fs/btrfs/{uuid}/devices"))?;
    if devices.next().transpose()?.map(|entry| fs::canonicalize(entry.path())).transpose()? != Some(expected)
        || devices.next().is_some()
    {
        return Err(invalid("Btrfs mounted with a device outside the signed selection"));
    }
    Ok(())
}

pub fn mount_btrfs(source: &Path, uuid: &str, target: &str) -> io::Result<()> {
    verify_superblock(source, "btrfs", uuid, None)?;
    // The kernel mounts from the primary superblock at 64 KiB. Its little-endian
    // num_devices field is at byte 0x88, as defined in linux/btrfs_tree.h.
    let mut count = [0u8; 8];
    File::open(source)?.read_exact_at(&mut count, 0x10000 + 0x88)?;
    if u64::from_le_bytes(count) != 1 {
        return Err(invalid("the selected Btrfs filesystem must have exactly one device"));
    }
    fs::DirBuilder::new().mode(0o700).create(target)?;
    run(Command::new("/usr/bin/mount")
        .args(["--internal-only", "-t", "btrfs", "-o", "rw,nodev,nosuid,noexec,subvolid=5"])
        .arg(source).arg(target))?;
    if let Err(error) = verify_btrfs_mount(source, uuid, target) {
        let _ = run(Command::new("/usr/bin/umount").arg(target));
        return Err(error);
    }
    Ok(())
}

pub fn identity<'a>(line: &'a str, key: &str, groups: &[usize], separator: char) -> io::Result<&'a str> {
    let value = line.strip_prefix(key).ok_or_else(|| invalid("unexpected storage field"))?;
    let mut parts = value.split(separator);
    for size in groups {
        let Some(part) = parts.next() else {
            return Err(invalid("missing storage identity component"));
        };
        if part.len() != *size || !part.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(invalid("invalid storage identity"));
        }
    }
    if parts.next().is_some() {
        return Err(invalid("extra storage identity component"));
    }
    Ok(value)
}
