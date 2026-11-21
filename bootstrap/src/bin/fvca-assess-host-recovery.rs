#![forbid(unsafe_code)]

use std::alloc::System;
use std::fs::{self, File};
use std::io;
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
const MOUNT: &str = "/run/fvca-host-recovery/pool";
const CRYPTSETUP: &str = "/usr/bin/cryptsetup";

struct Selection<'a> {
    partition: &'a str,
    luks: &'a str,
    filesystem: &'a str,
    header_digest: &'a str,
    key_slot: &'a str,
    not_before: u64,
    expires: u64,
}

impl<'a> Selection<'a> {
    fn parse(text: &'a str) -> io::Result<Self> {
        if text.len() > 512 || !text.ends_with('\n') || !text.is_ascii() || text.contains('\r') {
            return Err(invalid("invalid signed Host recovery selection"));
        }
        let mut lines = text.lines();
        if lines.next() != Some("FVCA-HOST-RECOVERY-1") {
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
        let not_before = number(field("not_before=")?)?;
        let expires = number(field("expires=")?)?;
        if lines.next().is_some() || number(key_slot)? > 31
            || !matches!(expires.checked_sub(not_before), Some(1..=86400))
        {
            return Err(invalid("invalid Host recovery keyslot or validity window"));
        }
        Ok(Self { partition, luks, filesystem, header_digest, key_slot, not_before, expires })
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

fn assess() -> io::Result<()> {
    fvca_allocator_binding::require_allocator()?;
    if fs::read_to_string("/proc/cmdline")? != fs::read_to_string("/usr/lib/fvca/host-recovery.cmdline")? {
        return Err(invalid("the kernel command line differs from the signed Host recovery policy"));
    }
    kernel_policy::require_signed_modules()?;
    let text = fs::read_to_string(SELECTION)?;
    let selection = Selection::parse(&text)?;
    selection.verify_time()?;
    kernel_policy::load_modules(&[
        "virtio_pci", "virtio_blk", "nvme", "dm_crypt", "dm_integrity", "authenc", "hmac", "xts", "btrfs",
    ])?;
    kernel_policy::seal()?;
    let source = locate(selection.partition)?;
    let partition = sys_block(&source)?;
    if !partition.join("partition").is_file() {
        return Err(invalid("authorized Host recovery member is not a partition"));
    }
    run(Command::new("/usr/bin/blockdev").arg("--setro").arg(&source))?;
    verify_readonly(&partition)?;
    verify_superblock(&source, "crypto_LUKS", selection.luks, Some("2"))?;
    run(Command::new(CRYPTSETUP)
        .args(["luksHeaderBackup", "--header-backup-file", HEADER])
        .arg(&source))?;
    let header = File::open(HEADER)?;
    if !header.metadata()?.is_file() || recovery::sha256(header)? != selection.header_digest {
        return Err(invalid("live LUKS2 header differs from the signed recovery header"));
    }
    selection.verify_time()?;
    open_member(&selection, &source)?;
    let result = (|| {
        fs::remove_file(HEADER)?;
        selection.verify_time()?;
        let volume = Path::new(VOLUME);
        let mapped = sys_block(&fs::canonicalize(volume)?)?;
        let journal = storage_integrity::verify(&mapped, &partition)?;
        for device in [&partition, &journal, &mapped] {
            verify_readonly(device)?;
        }
        btrfs::assess_host_member(volume, selection.filesystem, MOUNT)
    })();
    run(Command::new(CRYPTSETUP).args(["close", MAPPER]))?;
    result?;
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
