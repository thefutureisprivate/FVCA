//! Select and trial verified direct-boot releases on the Hypervisor.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fvca_initrd_bootstrap::{guest_boot, invalid, recovery, run, runtime};

use fvca_libvirt_boundary::{Connection, RUNNING};
use fvca_trial_authorization::guest::{
    self, ATTEMPT_LIMIT as LIMIT, ENROLLMENT_LIMIT, ENVELOPE_LIMIT, FENCE, IMAGE_LIMIT, STORE,
    Trial,
};

use super::{CAPTURE_LOCK, OPERATION_LOCK, UUID, capture};

const MOUNT: &str = "/run/fvca/guest-trial-verify";
const DISSECT: &str = "/usr/bin/systemd-dissect";
const RUN: &str = "/run/fvca";
const RELEASES: &str = "/run/fvca/guest-releases";
const WORK: &str = "guest-trial-work";
const WORKER: &str = "fvca-guest-trial-attempt.service";
const WORKER_DROPIN: &str = "/run/systemd/system/fvca-guest-trial-attempt.service.d";
const DEADLINE: &str = "50-fvca-deadline.conf";
const O_NOFOLLOW: i32 = 0o400000;
const O_NONBLOCK: i32 = 0o4000;

fn require_fresh(trial: &Trial<'_>) -> io::Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs();
    trial.require_fresh(now)
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

pub(super) fn require_verity_mount(path: &Path) -> io::Result<()> {
    let mount = Command::new("/usr/bin/findmnt")
        .env_clear()
        .arg("--mountpoint")
        .arg(path)
        .args([
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
    Ok(())
}

fn verify_mounted(root: &Path, trial: &Trial<'_>) -> io::Result<()> {
    require_verity_mount(root)?;
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

fn enrollment() -> io::Result<([u8; 32], u64)> {
    let base = read(
        Path::new(guest_boot::TRIAL_ENROLLMENT),
        ENROLLMENT_LIMIT as u64,
    )?;
    let (key, epoch) = guest::enrollment(&base)?;
    Ok((*key, epoch))
}

fn signed<'a>(key: &[u8; 32], approval: &'a [u8]) -> io::Result<Trial<'a>> {
    let (proof, body) = approval
        .split_first_chunk::<64>()
        .ok_or_else(|| invalid("truncated signed Guest trial"))?;
    fvca_signature_boundary::verify_ed25519(key, proof, body)?;
    Trial::parse(std::str::from_utf8(body).map_err(io::Error::other)?)
}

fn store() -> io::Result<&'static Path> {
    super::verify_pool()?;
    let path = Path::new(STORE);
    super::private_directory(path)?;
    Ok(path)
}

fn mount_image(trial: &Trial<'_>, target: &Path) -> io::Result<()> {
    let directory = Path::new(STORE).join(trial.selection.bundle);
    super::private_directory(&directory)?;
    let path: PathBuf = directory.join("guest-boot.raw");
    super::require_pool_path(&path)?;
    let file = private_file(&path, IMAGE_LIMIT)?;
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
        .args(["--mount", &pinned])
        .arg(target))?;
    run(Command::new("/usr/bin/mount")
        .args(["--internal-only", "-o", "remount,ro,nodev,nosuid,noexec"])
        .arg(target))?;
    verify_mounted(target, trial)
}

pub(super) fn verify() -> io::Result<()> {
    let (key, epoch) = enrollment()?;
    let approval = read(&store()?.join("pending-trial"), ENVELOPE_LIMIT as u64)?;
    let trial = signed(&key, &approval)?;
    require_current(&trial, &key, epoch)?;
    // The verification service's private namespace reclaims a partial mount on error.
    mount_image(&trial, Path::new(MOUNT))?;
    run(Command::new(DISSECT).args(["--umount", MOUNT]))?;
    require_fresh(&trial)?;
    println!(
        "FVCA_GUEST_TRIAL_PREPARED {} {} {} {}",
        trial.transaction, trial.candidate_epoch, trial.selection.bundle, trial.deadline
    );
    Ok(())
}

fn release_path(bundle: &str) -> PathBuf {
    Path::new(RELEASES).join(bundle)
}

pub(super) fn boot_directory(bundle: &str) -> io::Result<PathBuf> {
    let path = release_path(runtime::hash(bundle)?);
    if path.try_exists()? {
        Ok(path)
    } else {
        Ok(PathBuf::from(guest_boot::BOOT))
    }
}

fn mount_release(trial: &Trial<'_>) -> io::Result<()> {
    let target = release_path(trial.selection.bundle);
    fs::create_dir_all(RELEASES)?;
    match fs::create_dir(&target) {
        Ok(()) => mount_image(trial, &target),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            verify_mounted(&target, trial)
        }
        Err(error) => Err(error),
    }
}

fn unmount_release(bundle: &str) -> io::Result<()> {
    let target = release_path(bundle);
    if !target.try_exists()? {
        return Ok(());
    }
    let status = Command::new("/usr/bin/findmnt")
        .env_clear()
        .arg("--mountpoint")
        .arg(&target)
        .stdout(std::process::Stdio::null())
        .status()?;
    match status.code() {
        Some(0) => run(Command::new(DISSECT)
            .args(["--umount", "--rmdir"])
            .arg(&target)),
        Some(1) => fs::remove_dir(target),
        _ => Err(invalid("could not identify the Guest release mount")),
    }
}

fn optional(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match read(path, ENVELOPE_LIMIT as u64) {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn committed(key: &[u8; 32], enrolled: u64) -> io::Result<Option<Vec<u8>>> {
    let Some(approval) = optional(&Path::new(STORE).join("active"))? else {
        return Ok(None);
    };
    store()?;
    if signed(key, &approval)?.candidate_epoch < enrolled {
        return Err(invalid("the committed Guest is below the enrolled epoch"));
    }
    Ok(Some(approval))
}

fn require_current(trial: &Trial<'_>, key: &[u8; 32], enrolled: u64) -> io::Result<()> {
    let active = fs::read_to_string(guest_boot::SELECTION)?;
    let epoch = match committed(key, enrolled)? {
        Some(approval) => {
            let committed = signed(key, &approval)?;
            if committed.launch != active {
                return Err(invalid(
                    "the running Guest selection differs from the committed release",
                ));
            }
            committed.candidate_epoch
        }
        None => enrolled,
    };
    if trial.stable_epoch != epoch || trial.stable != guest_boot::parse(&active)?.bundle {
        return Err(invalid(
            "Guest trial differs from the enrolled running release",
        ));
    }
    require_fresh(trial)
}

fn publish_selection(trial: &Trial<'_>) -> io::Result<()> {
    capture::replace_record(Path::new(RUN), "guest-launch", trial.launch)
}

pub(super) fn prepare_active() -> io::Result<()> {
    if !Path::new(STORE).join("active").try_exists()? {
        return Ok(());
    }
    let (key, epoch) = enrollment()?;
    let approval = committed(&key, epoch)?
        .ok_or_else(|| invalid("the committed Guest selection disappeared"))?;
    let trial = signed(&key, &approval)?;
    if Path::new("/run/fvca/boot-trial-started").try_exists()?
        && guest_boot::parse(&fs::read_to_string(guest_boot::SELECTION)?)?.bundle
            != trial.selection.bundle
    {
        return Err(invalid(
            "the trial Hypervisor does not bind the committed Guest bundle",
        ));
    }
    mount_release(&trial)?;
    publish_selection(&trial)?;
    println!(
        "FVCA_GUEST_RELEASE_SELECTED {} {}",
        trial.selection.bundle, trial.candidate_epoch
    );
    Ok(())
}

pub(super) fn require_idle() -> io::Result<()> {
    if Path::new(RUN).join(FENCE).try_exists()? {
        return Err(invalid("a Guest release trial owns the lifecycle lease"));
    }
    Ok(())
}

fn prior_attempts(directory: &Path) -> io::Result<u8> {
    let mut count = 0;
    for attempt in 1..=LIMIT {
        if let Some(record) =
            capture::optional_record(&directory.join(format!("attempt-{attempt}")))?
        {
            recovery::uuid(
                record
                    .strip_suffix('\n')
                    .ok_or_else(|| invalid("invalid Guest attempt journal"))?,
            )?;
            if attempt != count + 1 {
                return Err(invalid(
                    "nonconsecutive reservations in the Guest attempt journal",
                ));
            }
            count = attempt;
        }
    }
    Ok(count)
}

fn stop_failed_guest() -> io::Result<()> {
    let connection = Connection::connect()?;
    if let Some(guest) = connection.lookup(UUID)? {
        guest.destroy()?;
        println!("FVCA_GUEST_TRIAL_FORCED_STOP crash-consistent");
    }
    super::release(&connection)
}

fn retire_pending(store: &Path, approval: &[u8]) -> io::Result<()> {
    let pending = store.join("pending-trial");
    if optional(&pending)?.as_deref() == Some(approval) {
        fs::remove_file(pending)?;
        File::open(store)?.sync_all()?;
    }
    Ok(())
}

fn configure_worker(trial: &Trial<'_>) -> io::Result<()> {
    let directory = Path::new(WORKER_DROPIN);
    fs::create_dir_all(directory)?;
    capture::replace_record(
        directory,
        DEADLINE,
        &format!("[Service]\nTimeoutStartSec={}s\n", trial.deadline),
    )?;
    run(Command::new("/usr/bin/systemctl")
        .env_clear()
        .arg("daemon-reload"))?;
    let loaded = Command::new("/usr/bin/systemctl")
        .env_clear()
        .args(["show", "--property=LoadState", "--value", WORKER])
        .output()?;
    if !loaded.status.success() || loaded.stdout != b"loaded\n" {
        return Err(invalid("the Guest trial worker unit did not load"));
    }
    Ok(())
}

fn run_attempt(trial: &Trial<'_>, number: u8) -> io::Result<bool> {
    let status = Command::new("/usr/bin/systemctl")
        .env_clear()
        .args(["start", WORKER])
        .status()?;
    if !status.success() {
        eprintln!(
            "FVCA_GUEST_TRIAL_ATTEMPT_FAILED {} {number} {status}",
            trial.transaction
        );
    }
    Ok(status.success())
}

pub(super) fn boot_attempt() -> io::Result<()> {
    let (key, epoch) = enrollment()?;
    let root = Path::new(RUN);
    let approval = read(&root.join(WORK), ENVELOPE_LIMIT as u64)?;
    let trial = signed(&key, &approval)?;
    if capture::optional_record(&root.join(FENCE))? != Some(format!("{}\n", trial.selection.bundle))
    {
        return Err(invalid("no matching Guest trial activation"));
    }
    require_current(&trial, &key, epoch)?;
    require_verity_mount(&release_path(trial.selection.bundle))?;
    super::launch_selection(trial.launch, Duration::from_secs(trial.deadline))
}

pub(super) fn activate() -> io::Result<()> {
    let _capture = capture::lease(Path::new(CAPTURE_LOCK))?;
    let _operation = capture::lease(Path::new(OPERATION_LOCK))?;
    capture::live::require_idle()?;
    capture::restore::require_idle()?;
    if Path::new("/run/fvca/boot-trial-started").try_exists()? {
        return Err(invalid(
            "a Hypervisor trial owns the running Guest composition",
        ));
    }
    let store = store()?;
    let (key, epoch) = enrollment()?;
    let approval = read(&store.join("pending-trial"), ENVELOPE_LIMIT as u64)?;
    let trial = signed(&key, &approval)?;
    require_current(&trial, &key, epoch)?;
    let directory = store.join(trial.selection.bundle);
    super::private_directory(&directory)?;
    let used = prior_attempts(&directory)?;
    if used == LIMIT {
        retire_pending(store, &approval)?;
        println!("FVCA_GUEST_TRIAL_EXHAUSTED {} {LIMIT}", trial.transaction);
        return Ok(());
    }
    let stable = fs::read_to_string(guest_boot::SELECTION)?;
    super::verified_definition(&guest_boot::parse(&stable)?)?;
    capture::live::require_instance(trial.stable)?;
    let connection = Connection::connect()?;
    let guest = connection
        .lookup(UUID)?
        .ok_or_else(|| invalid("the stable Guest is stopped"))?;
    if guest.state()? != RUNNING || guest.guest_frozen()? {
        return Err(invalid(
            "Guest trial requires a running and thawed stable Guest",
        ));
    }
    let root = Path::new(RUN);
    capture::publish(root, FENCE, &format!("{}\n", trial.selection.bundle))?;
    mount_release(&trial)?;
    capture::replace_bytes(root, WORK, &approval)?;
    configure_worker(&trial)?;
    require_fresh(&trial)?;
    super::shutdown()?;
    let (volume, disk) = super::verify_data()?;
    if capture::optional_record(Path::new(super::RECEIPT))?
        != Some(capture::stop_receipt(&volume, &disk)?)
    {
        return Err(invalid(
            "the stable Guest has no matching orderly shutdown receipt",
        ));
    }
    for number in used + 1..=LIMIT {
        require_fresh(&trial)?;
        if optional(&store.join("pending-trial"))?.as_deref() != Some(approval.as_slice()) {
            return Err(invalid("the pending Guest trial changed during activation"));
        }
        capture::publish(
            &directory,
            &format!("attempt-{number}"),
            &format!("{}\n", trial.transaction),
        )?;
        println!("FVCA_GUEST_TRIAL_ATTEMPT {} {number}", trial.transaction);
        if run_attempt(&trial, number)? {
            capture::live::require_instance(trial.selection.bundle)?;
            capture::replace_bytes(store, "active", &approval)?;
            publish_selection(&trial)?;
            retire_pending(store, &approval)?;
            unmount_release(trial.stable)?;
            clear_fence()?;
            println!(
                "FVCA_GUEST_TRIAL_COMMITTED {} {number} {}",
                trial.transaction, trial.selection.bundle
            );
            return Ok(());
        }
        stop_failed_guest()?;
    }
    super::launch()?;
    retire_pending(store, &approval)?;
    unmount_release(trial.selection.bundle)?;
    clear_fence()?;
    println!("FVCA_GUEST_TRIAL_EXHAUSTED {} {LIMIT}", trial.transaction);
    Ok(())
}

fn clear_fence() -> io::Result<()> {
    let root = Path::new(RUN);
    match fs::remove_file(root.join(WORK)) {
        Ok(()) => (),
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error),
    }
    match fs::remove_file(Path::new(WORKER_DROPIN).join(DEADLINE)) {
        Ok(()) => run(Command::new("/usr/bin/systemctl")
            .env_clear()
            .arg("daemon-reload"))?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error),
    }
    fs::remove_file(root.join(FENCE))
}

pub(super) fn recover() -> io::Result<()> {
    let root = Path::new(RUN);
    let Some(fence) = capture::optional_record(&root.join(FENCE))? else {
        return Ok(());
    };
    let candidate = runtime::hash(fence.trim_end())?;
    let _capture = capture::lease_for_activation_recovery()?;
    let _operation = capture::lease(Path::new(OPERATION_LOCK))?;
    super::update::require_idle()?;
    if root.join(WORK).try_exists()? {
        run(Command::new("/usr/bin/systemctl")
            .env_clear()
            .args(["stop", WORKER]))?;
    }
    prepare_active()?;
    let payload = fs::read_to_string(guest_boot::SELECTION)?;
    let stable = guest_boot::parse(&payload)?;
    let connection = Connection::connect()?;
    let trusted = match connection.lookup(UUID)? {
        Some(guest) => {
            guest.state()? == RUNNING && capture::live::require_instance(stable.bundle).is_ok()
        }
        None => false,
    };
    if !trusted {
        stop_failed_guest()?;
        super::launch_selection(&payload, Duration::from_secs(75))?;
    }
    if candidate != stable.bundle {
        unmount_release(candidate)?;
    }
    clear_fence()?;
    println!("FVCA_GUEST_TRIAL_RECOVERED {}", stable.bundle);
    Ok(())
}
