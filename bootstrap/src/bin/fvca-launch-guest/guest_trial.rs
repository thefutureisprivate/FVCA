//! Verify a staged direct-boot candidate on the Hypervisor before any disruption.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use fvca_initrd_bootstrap::{guest_boot, invalid, recovery, run, runtime};

const STORE: &str = "/run/fvca/host-data/guest-updates";
const MOUNT: &str = "/run/fvca/guest-trial-verify";
const DISSECT: &str = "/usr/bin/systemd-dissect";
const MAX_IMAGE: u64 = 4 * 1024 * 1024 * 1024;
const O_NOFOLLOW: i32 = 0o400000;
const O_NONBLOCK: i32 = 0o4000;

struct Trial<'a> {
    transaction: &'a str,
    stable: &'a str,
    stable_epoch: u64,
    candidate_epoch: u64,
    deadline: u64,
    not_before: u64,
    expires: u64,
    image_digest: &'a str,
    image_bytes: u64,
    selection: guest_boot::Selection<'a>,
}

fn field<'a>(line: &'a str, key: &str) -> io::Result<&'a str> {
    line.strip_prefix(key)
        .ok_or_else(|| invalid("missing signed Guest trial field"))
}

fn number(line: &str, key: &str) -> io::Result<u64> {
    guest_boot::positive(field(line, key)?)
}

impl<'a> Trial<'a> {
    fn parse(body: &'a str) -> io::Result<Self> {
        let (authority, selection) = body.split_at(
            body.find("FVCA-GUEST-LAUNCH-1\n")
                .ok_or_else(|| invalid("missing Guest trial launch selection"))?,
        );
        let fields: Vec<_> = authority.split('\n').collect();
        let [
            "FVCA-GUEST-TRIAL-1",
            transaction,
            guest,
            stable,
            stable_epoch,
            candidate_epoch,
            from,
            until,
            deadline,
            "data=compatible",
            image_digest,
            image_bytes,
            "",
        ] = fields.as_slice()
        else {
            return Err(invalid("malformed Guest trial authorization"));
        };
        if field(guest, "guest=")?.as_bytes() != guest_boot::SERVICE_GUEST_UUID.to_bytes() {
            return Err(invalid("trial does not authorize this Service Guest"));
        }
        let stable = runtime::hash(field(stable, "stable_bundle=")?)?;
        let selection = guest_boot::parse(selection)?;
        let stable_epoch = number(stable_epoch, "stable_epoch=")?;
        let candidate_epoch = number(candidate_epoch, "candidate_epoch=")?;
        let not_before = number(from, "not_before=")?;
        let expires = number(until, "expires=")?;
        let deadline = number(deadline, "health_seconds=")?;
        let image_bytes = number(image_bytes, "candidate_image_bytes=")?;
        if stable == selection.bundle
            || candidate_epoch < stable_epoch
            || !expires
                .checked_sub(not_before)
                .is_some_and(|duration| (1..=86_400).contains(&duration))
            || !(10..=300).contains(&deadline)
            || image_bytes > MAX_IMAGE
            || !image_bytes.is_multiple_of(512)
        {
            return Err(invalid(
                "Guest trial exceeds its approved composition, epoch, time or size bounds",
            ));
        }
        Ok(Self {
            transaction: recovery::uuid(field(transaction, "transaction=")?)?,
            stable,
            stable_epoch,
            candidate_epoch,
            deadline,
            not_before,
            expires,
            image_digest: runtime::hash(field(image_digest, "candidate_image_sha256=")?)?,
            image_bytes,
            selection,
        })
    }

    fn require_fresh(&self) -> io::Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_secs();
        if !(self.not_before..self.expires).contains(&now) {
            return Err(invalid(
                "Guest trial is outside its signed validity interval",
            ));
        }
        Ok(())
    }
}

fn private_file(path: &Path, max: u64) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.nlink() != 1
        || !matches!(metadata.mode() & 0o7777, 0o600 | 0o400)
        || !(1..=max).contains(&metadata.len())
    {
        return Err(invalid(
            "Guest trial requires a bounded private regular file",
        ));
    }
    Ok(file)
}

fn read(path: &Path, max: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    private_file(path, max)?
        .take(max + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(invalid("Guest trial record exceeds its size bound"));
    }
    Ok(bytes)
}

fn mounted(trial: &Trial<'_>) -> io::Result<()> {
    run(Command::new("/usr/bin/mount").args([
        "--internal-only",
        "-o",
        "remount,ro,nodev,nosuid,noexec",
        MOUNT,
    ]))?;
    let mount = Command::new("/usr/bin/findmnt")
        .env_clear()
        .args([
            "--mountpoint",
            MOUNT,
            "--types",
            "erofs",
            "--options",
            "ro,nodev,nosuid,noexec",
            "--noheadings",
            "--raw",
            "--output",
            "MAJ:MIN",
        ])
        .output()?;
    let id = std::str::from_utf8(&mount.stdout)
        .map_err(io::Error::other)?
        .strip_suffix('\n')
        .and_then(|id| id.split_once(':'))
        .filter(|(major, minor)| {
            !major.is_empty()
                && !minor.is_empty()
                && major
                    .bytes()
                    .chain(minor.bytes())
                    .all(|byte| byte.is_ascii_digit())
        })
        .ok_or_else(|| invalid("the staged Guest bundle is not a restricted EROFS mount"))?;
    if !mount.status.success()
        || !fs::read_to_string(format!("/sys/dev/block/{}:{}/dm/uuid", id.0, id.1))?
            .starts_with("CRYPT-VERITY-")
    {
        return Err(invalid(
            "the staged Guest bundle lacks an active dm-verity device",
        ));
    }
    let root = Path::new(MOUNT);
    let mut seen = BTreeSet::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| invalid("invalid Guest bundle file name"))?;
        if !guest_boot::FILES.contains(&name.as_str())
            || !entry.file_type()?.is_file()
            || !seen.insert(name)
        {
            return Err(invalid("unexpected staged Guest bundle contents"));
        }
    }
    if seen.len() != guest_boot::FILES.len() {
        return Err(invalid("incomplete staged Guest bundle"));
    }
    super::verify_boot_files(root, &trial.selection)
}

pub(super) fn verify() -> io::Result<()> {
    let base = read(Path::new(guest_boot::TRIAL_ENROLLMENT), 53)?;
    let (key, epoch) = base
        .split_first_chunk::<32>()
        .ok_or_else(|| invalid("Guest trial authority is not enrolled"))?;
    let epoch = std::str::from_utf8(epoch)
        .map_err(io::Error::other)?
        .strip_suffix('\n')
        .ok_or_else(|| invalid("invalid enrolled Guest epoch"))?;
    let epoch = guest_boot::positive(epoch)?;
    super::verify_pool()?;
    let store = Path::new(STORE);
    super::private_directory(store)?;
    let approval = read(&store.join("pending-trial"), 4096)?;
    let (proof, body) = approval
        .split_first_chunk::<64>()
        .ok_or_else(|| invalid("truncated signed Guest trial"))?;
    fvca_signature_boundary::verify_ed25519(key, proof, body)?;
    let trial = Trial::parse(std::str::from_utf8(body).map_err(io::Error::other)?)?;
    let active = fs::read_to_string(guest_boot::SELECTION)?;
    if trial.stable_epoch != epoch || trial.stable != guest_boot::parse(&active)?.bundle {
        return Err(invalid(
            "Guest trial differs from the enrolled running release",
        ));
    }
    trial.require_fresh()?;
    let directory = store.join(trial.selection.bundle);
    super::private_directory(&directory)?;
    let path: PathBuf = directory.join("guest-boot.raw");
    super::require_pool_path(&path)?;
    let file = private_file(&path, MAX_IMAGE)?;
    if file.metadata()?.len() != trial.image_bytes
        || recovery::sha256(file.try_clone()?)? != trial.image_digest
    {
        return Err(invalid("staged Guest image differs from the signed trial"));
    }
    run(Command::new("/usr/bin/modprobe").args(["--ignore-install", "loop"]))?;
    let pinned = format!("/proc/{}/fd/{}", std::process::id(), file.as_raw_fd());
    run(Command::new(DISSECT)
        .args([
            "--read-only",
            "--fsck=no",
            "--growfs=no",
            "--discard=disabled",
            "--image-policy=root=signed:=absent",
        ])
        .arg(format!("--root-hash={}", trial.selection.bundle))
        .args(["--mount", &pinned, MOUNT]))?;
    let checked = mounted(&trial);
    let unmounted = run(Command::new(DISSECT).args(["--umount", MOUNT]));
    checked?;
    unmounted?;
    trial.require_fresh()?;
    println!(
        "FVCA_GUEST_TRIAL_PREPARED {} {} {} {}",
        trial.transaction, trial.candidate_epoch, trial.selection.bundle, trial.deadline
    );
    Ok(())
}
