#![forbid(unsafe_code)]

use std::alloc::System;
use std::fs::{self, File};
use std::io::{self, Read, Seek};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fvca_initrd_bootstrap::{
    btrfs, find_partition, invalid, kernel_policy, recovery, run, runtime, storage_integrity,
    sys_block, verify_superblock,
};

#[global_allocator]
static ALLOCATOR: System = System;

const SELECTION: &str = "/usr/lib/fvca/host-recovery";
const MAPPER: &str = "fvca-recovery";
const VOLUME: &str = "/dev/mapper/fvca-recovery";
const HEADER: &str = "/run/fvca-host-recovery/member.header";
const CURRENT: &str = "/run/fvca-host-recovery/current.header";
const MOUNT: &str = "/run/fvca-host-recovery/pool";
const CRYPTSETUP: &str = "/usr/bin/cryptsetup";
const LOSETUP: &str = "/usr/bin/losetup";
// Linux x86-64 block-device exclusive open.
const O_EXCL: i32 = 0o200;

struct HeaderMedia<'a> {
    partition: &'a str,
    bytes: u64,
}

struct Selection<'a> {
    partition: &'a str,
    luks: &'a str,
    filesystem: &'a str,
    header_digest: &'a str,
    key_slot: &'a str,
    media: Option<HeaderMedia<'a>>,
    restore_from: Option<&'a str>,
    not_before: u64,
    expires: u64,
}

impl<'a> Selection<'a> {
    fn parse(text: &'a str) -> io::Result<Self> {
        if text.len() > 512 || !text.ends_with('\n') || !text.is_ascii() || text.contains('\r') {
            return Err(invalid("invalid signed Host recovery selection"));
        }
        let mut lines = text.lines();
        if lines.next() != Some("FVCA-HOST-RECOVERY-2") {
            return Err(invalid("unknown Host recovery selection format"));
        }
        let mut field = |key| {
            lines.next().and_then(|line| line.strip_prefix(key))
                .ok_or_else(|| invalid("missing signed Host recovery field"))
        };
        let number = |value: &str| {
            value.parse::<u64>().ok().filter(|number| number.to_string() == value)
                .ok_or_else(|| invalid("invalid signed Host recovery number"))
        };
        let partition = recovery::uuid(field("partition=")?)?;
        let luks = recovery::uuid(field("luks=")?)?;
        let filesystem = recovery::uuid(field("filesystem=")?)?;
        let header_digest = runtime::hash(field("header_sha256=")?)?;
        let key_slot = field("key_slot=")?;
        let media = match field("header_media=")? {
            "none" => None,
            value => {
                let (uuid, bytes) = value.split_once(',')
                    .ok_or_else(|| invalid("invalid signed recovery media"))?;
                let bytes = number(bytes)?;
                if uuid == partition || !bytes.is_multiple_of(4096) || !(16384..=134217728).contains(&bytes) {
                    return Err(invalid("invalid signed recovery media extent"));
                }
                Some(HeaderMedia { partition: recovery::uuid(uuid)?, bytes })
            }
        };
        let restore_from = match field("restore_from=")? {
            "none" => None,
            digest if media.is_some() => Some(runtime::hash(digest)?),
            _ => return Err(invalid("header restoration requires signed backup media")),
        };
        let not_before = number(field("not_before=")?)?;
        let expires = number(field("expires=")?)?;
        if lines.next().is_some() || number(key_slot)? > 31
            || !matches!(expires.checked_sub(not_before), Some(1..=86400))
        {
            return Err(invalid("invalid Host recovery keyslot or validity window"));
        }
        Ok(Self { partition, luks, filesystem, header_digest, key_slot, media, restore_from, not_before, expires })
    }

    fn verify_time(&self) -> io::Result<()> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(io::Error::other)?.as_secs();
        if !(self.not_before..self.expires).contains(&now) {
            return Err(invalid("Host recovery authorization is outside its RTC validity window"));
        }
        Ok(())
    }
}

fn locate(uuid: &str) -> io::Result<PathBuf> {
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        if let Some(source) = find_partition(uuid)? {
            return Ok(source);
        }
        if Instant::now() >= deadline {
            return Err(invalid("the authorized recovery partition is unavailable"));
        }
        thread::sleep(Duration::from_millis(200));
    }
}

fn verify_readonly(device: &Path) -> io::Result<()> {
    if fs::read_to_string(device.join("ro"))? != "1\n" {
        return Err(invalid("Host recovery requires a read-only block path"));
    }
    Ok(())
}

fn with_write_barrier(
    source: &Path,
    pinned: &Path,
    partition: &Path,
    assess: impl FnOnce(&Path, &Path) -> io::Result<()>,
) -> io::Result<()> {
    // A block-device read-only ioctl alone warns on writes from stacked
    // drivers. The read-only loop driver rejects those writes, including
    // journal replay issued below the read-only dm-crypt mapping.
    let output = Command::new(LOSETUP).env_clear()
        .args(["--find", "--show", "--read-only", "--sector-size", "4096"])
        .arg(pinned)
        .output()?;
    if !output.status.success() {
        return Err(invalid("could not establish the Host recovery write barrier"));
    }
    let text = std::str::from_utf8(&output.stdout).map_err(io::Error::other)?;
    let path = text.strip_suffix('\n').ok_or_else(|| invalid("invalid recovery loop device"))?;
    if !path.strip_prefix("/dev/loop").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
    }) {
        return Err(invalid("invalid recovery loop device"));
    }
    let path = Path::new(path);
    let result = (|| {
        let block = sys_block(path)?;
        verify_readonly(&block)?;
        let loop_info = block.join("loop");
        let backing = fs::read_to_string(loop_info.join("backing_file"))?;
        if backing.strip_suffix('\n').map(Path::new) != Some(source)
            || fs::read_to_string(loop_info.join("offset"))? != "0\n"
            || fs::read_to_string(loop_info.join("sizelimit"))? != "0\n"
            || fs::read_to_string(block.join("size"))? != fs::read_to_string(partition.join("size"))?
        {
            return Err(invalid("Host recovery loop device does not cover the selected partition"));
        }
        assess(path, &block)
    })();
    run(Command::new(LOSETUP).arg("--detach").arg(path))?;
    result
}

fn open_member(selection: &Selection<'_>, source: &Path) -> io::Result<()> {
    let mut ask = Command::new("/usr/bin/systemd-ask-password")
        .env_clear()
        .args(["--no-tty", "--timeout=55", "--echo=masked", "-n", "Enter FVCA independent recovery credential:"])
        .stdout(Stdio::piped())
        .spawn()?;
    let opened = run(Command::new(CRYPTSETUP)
        .args([
            "open", "--type", "luks2", "--readonly", "--disable-external-tokens", "--header", HEADER,
            "--key-slot", selection.key_slot, "--key-file", "-",
        ])
        .arg(source)
        .arg(MAPPER)
        .stdin(ask.stdout.take().ok_or_else(|| invalid("missing recovery credential pipe"))?));
    if opened.is_err() {
        let _ = ask.kill();
        ask.wait()?;
        return opened;
    }
    let result = ask.wait().and_then(|status| {
        if status.success() {
            Ok(())
        } else {
            Err(invalid("independent recovery credential prompt did not complete"))
        }
    });
    if result.is_err() {
        run(Command::new(CRYPTSETUP).args(["close", MAPPER]))?;
    }
    result
}

fn load_header(selection: &Selection<'_>, source: &Path, partition: &Path) -> io::Result<()> {
    if let Some(media) = &selection.media {
        let media_device = fs::canonicalize(locate(media.partition)?)?;
        let block = sys_block(&media_device)?;
        let sectors = fs::read_to_string(block.join("size"))?.trim_end()
            .parse::<u64>().map_err(io::Error::other)?;
        if !block.join("partition").is_file() || block.parent() == partition.parent()
            || sectors.checked_mul(512) != Some(media.bytes)
        {
            return Err(invalid("backup media must be the authorized extent on a separate disk"));
        }
        let mut output = File::options().write(true).create_new(true).open(HEADER)?;
        if io::copy(&mut File::open(media_device)?.take(media.bytes), &mut output)? != media.bytes {
            return Err(invalid("incomplete backup header read"));
        }
    } else {
        verify_superblock(source, "crypto_LUKS", selection.luks, Some("2"))?;
        run(Command::new(CRYPTSETUP)
            .args(["luksHeaderBackup", "--header-backup-file", HEADER])
            .arg(source))?;
    }
    let header = File::open(HEADER)?;
    if !header.metadata()?.is_file() || recovery::sha256(header)? != selection.header_digest {
        return Err(invalid("LUKS2 header differs from the signed recovery header"));
    }
    verify_superblock(Path::new(HEADER), "crypto_LUKS", selection.luks, Some("2"))
}

fn assess_member(selection: &Selection<'_>, source: &Path, barrier: &Path) -> io::Result<()> {
    selection.verify_time()?;
    open_member(selection, source)?;
    let result = (|| {
        selection.verify_time()?;
        let volume = Path::new(VOLUME);
        let mapped = sys_block(&fs::canonicalize(volume)?)?;
        let journal = storage_integrity::verify(&mapped, barrier)?;
        for device in [barrier, &journal, &mapped] {
            verify_readonly(device)?;
        }
        btrfs::assess_host_member(volume, selection.filesystem, MOUNT)
    })();
    run(Command::new(CRYPTSETUP).args(["close", MAPPER]))?;
    result
}

fn prefix_hash(mut source: File, bytes: u64) -> io::Result<String> {
    let mut copy = File::options().read(true).write(true).create_new(true).open(CURRENT)?;
    fs::remove_file(CURRENT)?;
    source.rewind()?;
    if io::copy(&mut source.take(bytes), &mut copy)? != bytes {
        return Err(invalid("incomplete on-disk header read"));
    }
    copy.rewind()?;
    recovery::sha256(copy)
}

fn require_restore_prefix(selection: &Selection<'_>, source: File, bytes: u64, previous: &str) -> io::Result<bool> {
    let observed = prefix_hash(source, bytes)?;
    if observed == selection.header_digest {
        return Ok(true);
    }
    if observed != previous {
        return Err(invalid("on-disk header does not match the authorized restore precondition"));
    }
    Ok(false)
}

fn restore_header(selection: &Selection<'_>, pinned: &Path, bytes: u64, previous: &str) -> io::Result<()> {
    // Claim the pinned partition only after the read-only mapping is closed.
    let lease = File::options().read(true).custom_flags(O_EXCL).open(pinned)?;
    let already_restored = require_restore_prefix(selection, lease.try_clone()?, bytes, previous)?;
    selection.verify_time()?;
    if !already_restored {
        run(Command::new(CRYPTSETUP)
            .args(["luksHeaderRestore", "--type", "luks2", "--batch-mode", "--header-backup-file", HEADER])
            .arg(pinned)
            .stdin(Stdio::null()))?;
        lease.sync_all()?;
        if prefix_hash(lease.try_clone()?, bytes)? != selection.header_digest {
            return Err(invalid("restored LUKS2 header failed exact readback"));
        }
    }
    verify_superblock(pinned, "crypto_LUKS", selection.luks, Some("2"))
}

fn assess() -> io::Result<()> {
    fvca_allocator_binding::require_allocator()?;
    kernel_policy::require_signed_modules()?;
    let text = fs::read_to_string(SELECTION)?;
    let selection = Selection::parse(&text)?;
    selection.verify_time()?;
    kernel_policy::load_modules(&[
        "virtio_pci", "virtio_blk", "nvme", "loop", "dm_crypt", "dm_integrity",
        "authenc", "hmac", "xts", "btrfs",
    ])?;
    kernel_policy::seal()?;
    let source = fs::canonicalize(locate(selection.partition)?)?;
    let partition = sys_block(&source)?;
    if !partition.join("partition").is_file() {
        return Err(invalid("authorized Host recovery member is not a partition"));
    }
    let disk = File::open(&source)?;
    let pinned = PathBuf::from(format!("/proc/{}/fd/{}", std::process::id(), disk.as_raw_fd()));
    let restore = selection.restore_from.zip(selection.media.as_ref().map(|media| media.bytes));
    if let Some((previous, bytes)) = restore {
        require_restore_prefix(&selection, disk.try_clone()?, bytes, previous)?;
    }
    with_write_barrier(&source, &pinned, &partition, |backing, barrier| {
        load_header(&selection, backing, &partition)?;
        assess_member(&selection, backing, barrier)
    })?;
    if let Some((previous, bytes)) = restore {
        restore_header(&selection, &pinned, bytes, previous)?;
    }
    fs::remove_file(HEADER)?;
    if restore.is_some() {
        println!("FVCA_HOST_HEADER_RESTORED {}", selection.luks);
    }
    println!("FVCA_HOST_RECOVERY_VERIFIED {} raid1 read-only", selection.filesystem);
    Ok(())
}

fn main() -> ExitCode {
    match assess() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("FVCA_HOST_RECOVERY_REFUSED {error}");
            ExitCode::FAILURE
        }
    }
}
