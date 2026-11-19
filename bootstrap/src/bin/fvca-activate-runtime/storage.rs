use std::fs;
use std::io;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use fvca_initrd_bootstrap::{find_partition, identity, invalid, mount_btrfs, run, sys_block, verify_superblock};
use super::hash;

#[path = "tpm.rs"]
mod tpm;

const POLICY: &str = "/usr/lib/fvca/host-storage";
const ARRAY: &str = "/dev/md0";
const MAPPER: &str = "fvca-host-data";
const VOLUME: &str = "/dev/mapper/fvca-host-data";
const DATA: &str = "/run/fvca/host-data";
const MDADM: &str = "/usr/bin/mdadm";
const CRYPTSETUP: &str = "/usr/bin/systemd-cryptsetup";

enum Unlock<'a> {
    DevelopmentPassphrase,
    Tpm { token: &'a str, digest: &'a str },
}

struct Selection<'a> {
    unlock: Unlock<'a>,
    member_a: &'a str,
    member_b: &'a str,
    raid: &'a str,
    luks: &'a str,
    filesystem: &'a str,
}

fn selection(text: &str) -> io::Result<Selection<'_>> {
    let fields: Vec<_> = text.split('\n').collect();
    let ["FVCA-HOST-STORAGE-2", unlock, a, b, raid, luks, "filesystem=btrfs", filesystem, rest @ ..] =
        fields.as_slice()
    else {
        return Err(invalid("malformed Hypervisor storage selection"));
    };
    let uuid = [8, 4, 4, 4, 12];
    let member_a = identity(a, "member_a=", &uuid, '-')?;
    let member_b = identity(b, "member_b=", &uuid, '-')?;
    if member_a == member_b {
        return Err(invalid("storage selection must name two distinct members"));
    }
    let unlock = match (*unlock, rest) {
        ("unlock=development-passphrase", [""]) => Unlock::DevelopmentPassphrase,
        ("unlock=tpm2-pin", [field, ""]) => {
            let Some((token, digest)) = field.strip_prefix("token=").and_then(|value| value.split_once(',')) else {
                return Err(invalid("missing TPM token authorization"));
            };
            let number = token.parse::<u8>().map_err(|_| invalid("invalid TPM token index"))?;
            if number > 31 || number.to_string() != token {
                return Err(invalid("invalid TPM token index"));
            }
            Unlock::Tpm { token, digest: hash(digest)? }
        }
        _ => return Err(invalid("unsupported storage unlock policy")),
    };
    Ok(Selection {
        unlock,
        member_a,
        member_b,
        raid: identity(raid, "raid=", &[8, 8, 8, 8], ':')?,
        luks: identity(luks, "luks=", &uuid, '-')?,
        filesystem: identity(filesystem, "filesystem_uuid=", &uuid, '-')?,
    })
}

fn members(selection: &Selection<'_>) -> io::Result<(PathBuf, PathBuf)> {
    let deadline = Instant::now() + Duration::from_secs(6);
    loop {
        if let (Some(a), Some(b)) = (find_partition(selection.member_a)?, find_partition(selection.member_b)?) {
            // Distinct partitions on the same drive cannot provide redundancy.
            if parent_device(&a)? == parent_device(&b)? {
                return Err(invalid("mirror members reside on the same disk"));
            }
            return Ok((a, b));
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::NotFound, "both authorized storage members are required"));
        }
        thread::sleep(Duration::from_millis(200));
    }
}

fn parent_device(path: &Path) -> io::Result<PathBuf> {
    let partition = sys_block(path)?;
    if !partition.join("partition").try_exists()? {
        return Err(invalid("a mirror member must be a partition"));
    }
    partition.parent().map(Path::to_path_buf).ok_or_else(|| invalid("missing parent block device"))
}

fn verify_array(a: &Path, b: &Path) -> io::Result<()> {
    if !fs::metadata(ARRAY)?.file_type().is_block_device() {
        return Err(invalid("assembled array is not a block device"));
    }
    let sys = sys_block(&fs::canonicalize(ARRAY)?)?;
    for (name, expected) in [("level", "raid1"), ("raid_disks", "2"), ("degraded", "0"), ("metadata_version", "1.2")] {
        if fs::read_to_string(sys.join("md").join(name))?.trim_end() != expected {
            return Err(invalid("assembled array is not a healthy two-member native RAID1"));
        }
    }
    let mut actual = fs::read_dir(sys.join("slaves"))?
        .map(|entry| entry.and_then(|entry| fs::canonicalize(entry.path())))
        .collect::<io::Result<Vec<_>>>()?;
    actual.sort();
    let mut selected = [sys_block(a)?, sys_block(b)?];
    selected.sort();
    if actual != selected {
        return Err(invalid("assembled array has unselected members"));
    }
    Ok(())
}

fn unlock_development() -> io::Result<()> {
    let status = Command::new(CRYPTSETUP).env_clear()
        .env("SYSTEMD_CRYPTSETUP_USE_TOKEN_MODULE", "0").args([
        "attach", MAPPER, ARRAY, "none", "luks,tries=1,timeout=55,password-cache=no",
    ]).status()?;
    if !status.success() {
        return Err(io::Error::other(format!("development passphrase unlock exited with {status}")));
    }
    Ok(())
}

fn open_data(selection: &Selection<'_>, a: &Path, b: &Path) -> io::Result<()> {
    verify_array(a, b)?;
    verify_superblock(Path::new(ARRAY), "crypto_LUKS", selection.luks, Some("2"))?;
    run(Command::new(MDADM).args(["--readwrite", ARRAY]))?;
    match selection.unlock {
        Unlock::DevelopmentPassphrase => unlock_development()?,
        Unlock::Tpm { token, digest } => tpm::unlock(selection.luks, token, digest)?,
    }
    if let Err(error) = mount_btrfs(Path::new(VOLUME), selection.filesystem, DATA) {
        let _ = run(Command::new(CRYPTSETUP).args(["detach", MAPPER]));
        return Err(error);
    }
    Ok(())
}

pub(super) fn activate_if_selected() -> io::Result<()> {
    let policy = match fs::read_to_string(POLICY) {
        Ok(policy) => policy,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let selection = selection(&policy)?;
    let (a, b) = members(&selection)?;
    bind_readiness_probe()?;
    run(Command::new("/usr/bin/modprobe").args(["--ignore-install", "raid1"]))?;
    run(Command::new(MDADM).args([
        "--assemble", "--config=/dev/null", "--readonly", "--uuid", selection.raid, ARRAY,
    ]).args([&a, &b]))?;
    if let Err(error) = open_data(&selection, &a, &b) {
        let _ = run(Command::new(MDADM).args(["--stop", ARRAY]));
        return Err(error);
    }
    println!("FVCA_HOST_STORAGE_ACTIVE");
    Ok(())
}

fn bind_readiness_probe() -> io::Result<()> {
    let drop_in = "/run/systemd/system/fvca-vm-runtime-probe.service.d";
    fs::create_dir_all(drop_in)?;
    fs::write(format!("{drop_in}/10-storage.conf"), concat!(
        "[Service]\n",
        "ExecStartPre=/usr/bin/findmnt --mountpoint /run/fvca/host-data",
        " --source /dev/mapper/fvca-host-data --types btrfs --options rw,nodev,nosuid,noexec\n",
    ))
}
