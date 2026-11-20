#![forbid(unsafe_code)]

use std::alloc::System;
use std::ffi::{CStr, CString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, fchown};
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use fvca_initrd_bootstrap::{guest_boot::{self, SERVICE_GUEST_UUID as UUID}, invalid, run, vm_confinement};
use fvca_libvirt_boundary::{Connection, Domain, EventLoop, PAUSED, RUNNING};
use fvca_trial_authorization::GUEST_CAPTURE_LOCK as CAPTURE_LOCK;

#[path = "fvca-launch-guest/capture.rs"]
mod capture;
#[path = "fvca-launch-guest/guest_trial.rs"]
mod guest_trial;

#[global_allocator]
static ALLOCATOR: System = System;

const POOL: &str = "/run/fvca/host-data";
const VM_PARENT: &str = "/run/fvca/host-data/vms";
const VM_DIRECTORY: &str = "/run/fvca/host-data/vms/service-guest";
const DISK: &str = "/run/fvca/host-data/vms/service-guest/data.raw";
const ALIAS: &str = "/run/fvca/guest-state.raw";
const PID: &str = "/run/libvirt/qemu/fvca-service-guest.pid";
const RECEIPT: &str = "/run/fvca/guest-clean-stop";
const OPERATION_LOCK: &str = "/run/fvca/guest-operation.lock";
const ATTACHMENT: &str = "data-attachment";

#[path = "fvca-launch-guest/update.rs"]
mod update;

fn verify_boot_files(directory: &Path, selection: &guest_boot::Selection<'_>) -> io::Result<()> {
    let mut checksum = Command::new("/usr/bin/sha256sum").env_clear()
        .current_dir(directory)
        .args(["--strict", "--check", "--status", "-"])
        .stdin(Stdio::piped()).spawn()?;
    let written = checksum.stdin.take().expect("checksum input is piped").write_all(selection.checksums.as_bytes());
    let status = checksum.wait()?;
    written?;
    if !status.success() {
        return Err(invalid("Guest boot files differ from the UKI-authorized selection"));
    }
    Ok(())
}

fn verified_definition(selection: &guest_boot::Selection<'_>) -> io::Result<CString> {
    let boot = guest_trial::boot_directory(selection.bundle)?;
    if boot == Path::new(guest_boot::BOOT) {
        run(Command::new("/usr/bin/findmnt").args([
            "--mountpoint", guest_boot::BOOT, "--source", "/dev/mapper/fvca-guest-boot",
            "--types", "erofs", "--options", "ro,nodev,nosuid,noexec",
        ]).stdout(Stdio::null()))?;
    } else {
        guest_trial::require_verity_mount(&boot)?;
    }
    verify_boot_files(&boot, selection)?;
    let mut xml = fs::read_to_string(boot.join("domain.xml"))?;
    if boot != Path::new(guest_boot::BOOT) {
        // The signed machine names four boot files at the original mount. The
        // only rebinding is to the same verified files at the selected mount.
        let prefix = format!("{}/", guest_boot::BOOT);
        if xml.matches(&prefix).count() != 4 {
            return Err(invalid("the approved machine has an unexpected boot file layout"));
        }
        xml = xml.replace(&prefix, &format!("{}/", boot.display()));
    }
    CString::new(xml).map_err(io::Error::other)
}

fn verify_pool() -> io::Result<File> {
    run(Command::new("/usr/bin/findmnt").args([
        "--mountpoint", POOL, "--types", "btrfs", "--options", "rw,nodev,nosuid,noexec",
    ]).stdout(Stdio::null()))?;
    private_directory(Path::new(POOL))
}

fn private_directory(path: &Path) -> io::Result<File> {
    let directory = fs::symlink_metadata(path)?;
    if !directory.is_dir() || directory.uid() != 0 || directory.gid() != 0 || directory.mode() & 0o7777 != 0o700 {
        return Err(invalid("the Guest storage directory must be private and owned by root"));
    }
    File::open(path)
}

fn raw_disk_metadata(path: &Path) -> io::Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.mode() & 0o7777 != 0o600
        || metadata.len() == 0 || !metadata.len().is_multiple_of(512)
    {
        return Err(invalid("Guest data must be a private, sector-aligned raw file"));
    }
    Ok(metadata)
}

fn raw_disk(path: &Path) -> io::Result<File> {
    let metadata = raw_disk_metadata(path)?;
    if metadata.uid() != 0 || metadata.gid() != 0 {
        return Err(invalid("the stopped Guest disk must be owned by root"));
    }
    let disk = File::open(path)?;
    fvca_btrfs_boundary::require_cow_and_checksums(&disk)?;
    Ok(disk)
}

fn verify_storage_directory() -> io::Result<File> {
    verify_pool()?;
    for path in [VM_PARENT, VM_DIRECTORY] {
        private_directory(Path::new(path))?;
    }
    let root = File::open(VM_DIRECTORY)?;
    if root.metadata()?.ino() != 256 {
        return Err(invalid("Guest storage must use one Btrfs subvolume"));
    }
    let entries = fs::read_dir(VM_DIRECTORY)?.map(|entry| entry.map(|entry| entry.file_name())).collect::<io::Result<Vec<_>>>()?;
    if entries != ["data.raw"] {
        return Err(invalid("unexpected persistent files in the registered Guest subvolume"));
    }
    require_pool_path(Path::new(DISK))?;
    fvca_btrfs_boundary::require_cow_and_checksums(&root)?;
    Ok(root)
}

fn require_pool_path(path: &Path) -> io::Result<()> {
    let mount = Command::new("/usr/bin/findmnt").env_clear()
        .arg("--target").arg(path).args(["--noheadings", "--raw", "--output", "TARGET"])
        .output()?;
    if !mount.status.success() || mount.stdout != format!("{POOL}\n").as_bytes() {
        return Err(invalid("Guest data must reside in the authorized Host pool"));
    }
    Ok(())
}

fn verify_data() -> io::Result<(File, File)> {
    Ok((verify_storage_directory()?, raw_disk(Path::new(DISK))?))
}

fn invalidate_receipt() -> io::Result<()> {
    match fs::remove_file(RECEIPT) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

fn attachment_record(root: &File, metadata: &fs::Metadata) -> io::Result<String> {
    let volume = fvca_btrfs_boundary::subvolume(root)?;
    let fsid = fvca_btrfs_boundary::filesystem_uuid(&verify_pool()?)?;
    if volume.read_only || !matches!((metadata.uid(), metadata.gid()), (0, 0) | (107, 107)) {
        return Err(invalid("unexpected storage identity for the Guest attachment"));
    }
    Ok(format!("FVCA-GUEST-ATTACHMENT-1\npool={fsid}\nsubvolume={}\nsubvolume_id={}\ninode={}\nbytes={}\n",
               volume.uuid, volume.id, metadata.ino(), metadata.len()))
}

fn clear_attachment(dir: &Path) -> io::Result<()> {
    fs::remove_file(dir.join(ATTACHMENT))?;
    private_directory(dir)?.sync_all()
}

fn reclaim_attachment() -> io::Result<()> {
    let dir = Path::new(VM_PARENT);
    let Some(record) = capture::optional_record(&dir.join(ATTACHMENT))? else { return Ok(()); };
    if Path::new(PID).try_exists()? || Path::new(ALIAS).try_exists()? {
        return Err(invalid("Guest attachment recovery requires the prior disk attachment to be absent"));
    }
    let root = verify_storage_directory()?;
    let metadata = raw_disk_metadata(Path::new(DISK))?;
    if record != attachment_record(&root, &metadata)? {
        return Err(invalid("the registered disk differs from its durable attachment record"));
    }
    // Check identity with metadata only. The normal virt_image_t label also
    // denies init_t a content read until the detached disk has been relabelled.
    run(Command::new("/usr/bin/chcon").args(["--no-dereference", "system_u:object_r:fvca_host_data_t:s0", DISK]))?;
    let disk = File::open(DISK)?;
    let opened = disk.metadata()?;
    if (opened.dev(), opened.ino()) != (metadata.dev(), metadata.ino()) {
        return Err(invalid("the Guest disk changed during attachment recovery"));
    }
    fvca_btrfs_boundary::require_cow_and_checksums(&disk)?;
    if (metadata.uid(), metadata.gid()) != (0, 0) {
        fchown(&disk, Some(0), Some(0))?;
    }
    disk.sync_all()?;
    clear_attachment(dir)?;
    println!("FVCA_GUEST_ATTACHMENT_RECLAIMED");
    Ok(())
}

fn prepare_data() -> io::Result<()> {
    if Path::new(PID).try_exists()? || Path::new(ALIAS).try_exists()? {
        return Err(invalid("the prior Guest attachment is still present"));
    }
    reclaim_attachment()?;
    let (root, disk) = verify_data()?;
    invalidate_receipt()?;
    // Keep the pool private while giving sVirt one file to label for QEMU.
    capture::publish(Path::new(VM_PARENT), ATTACHMENT, &attachment_record(&root, &disk.metadata()?)?)?;
    run(Command::new("/usr/bin/chcon").args(["system_u:object_r:virt_image_t:s0", DISK]))?;
    OpenOptions::new().write(true).create_new(true).mode(0o600).open(ALIAS)?;
    run(Command::new("/usr/bin/mount").args(["--internal-only", "--bind", DISK, ALIAS]))
}

fn wait_for_boot(domain: &Domain<'_>, runtime: &str, events: &EventLoop, timeout: Duration) -> io::Result<()> {
    if domain.state()? != PAUSED {
        return Err(invalid("libvirt did not create the Guest paused"));
    }
    let pid: u32 = fs::read_to_string(PID)?.trim().parse().map_err(io::Error::other)?;
    if pid <= 1 {
        return Err(invalid("invalid Service Guest QEMU PID"));
    }
    vm_confinement::check_process(&Path::new("/proc").join(pid.to_string()))?;
    let mut console = domain.console()?;
    domain.resume()?;
    let expected = format!("FVCA_OCI_RUNTIME_ACTIVE {runtime}");
    let markers = [b"FVCA_DIRECT_BOOT_POLICY_ACTIVE".as_slice(), expected.as_bytes(), b"FVCA_DEV_BASE_READY"];
    let mut seen = [false; 3];
    let mut buffer = [0; 4096];
    let mut tail = Vec::with_capacity(buffer.len() + 128);
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let count = console.receive(&mut buffer)?;
        if count == 0 {
            events.poll()?;
            continue;
        }
        tail.extend_from_slice(&buffer[..count]);
        for (found, marker) in seen.iter_mut().zip(markers) {
            *found |= tail.windows(marker.len()).any(|bytes| bytes == marker);
        }
        if seen.into_iter().all(|found| found) && domain.state()? == RUNNING {
            domain.require_guest_agent()?;
            println!("FVCA_SERVICE_GUEST_AGENT_READY");
            return Ok(());
        }
        if tail.windows(b"FVCA_BOOT_FAILED".len()).any(|bytes| bytes == b"FVCA_BOOT_FAILED") {
            return Err(invalid("the Service Guest reported boot failure"));
        }
        tail.drain(..tail.len().saturating_sub(128));
    }
    Err(io::Error::new(io::ErrorKind::TimedOut, format!(
        "the Service Guest did not reach readiness (direct boot {}, verified runtime {}, root readiness {})",
        seen[0], seen[1], seen[2],
    )))
}

fn launch() -> io::Result<()> {
    guest_trial::prepare_active()?;
    let payload = fs::read_to_string(guest_boot::SELECTION)?;
    launch_selection(&payload, Duration::from_secs(75))
}

fn launch_selection(payload: &str, timeout: Duration) -> io::Result<()> {
    let selection = guest_boot::parse(payload)?;
    capture::restore::authorize_launch(selection.bundle)?;
    let xml = verified_definition(&selection)?;
    let events = EventLoop::register()?;
    let connection = Connection::connect()?;
    start(&connection, &events, &selection, &xml, timeout)
}

fn start(connection: &Connection, events: &EventLoop, selection: &guest_boot::Selection<'_>, xml: &CStr, timeout: Duration) -> io::Result<()> {
    if connection.lookup(UUID)?.is_some() {
        return Err(invalid("the registered Guest already exists"));
    }
    prepare_data().map_err(|error| io::Error::other(format!("Guest data preparation failed: {error}")))?;
    let domain = connection.start_registered(xml)?;
    if let Err(error) = wait_for_boot(&domain, selection.runtime, events, timeout)
        .and_then(|()| capture::live::record_launch(selection.bundle))
    {
        if let Err(cleanup) = domain.destroy() {
            eprintln!("FVCA could not stop the failed Guest: {cleanup}");
        }
        return Err(error);
    }
    println!("FVCA_SERVICE_GUEST_READY {} {}", selection.core, selection.runtime);
    Ok(())
}

fn shutdown() -> io::Result<()> {
    let events = EventLoop::register()?;
    let connection = Connection::connect()?;
    if stop(&connection, &events)? {
        release(&connection)?;
        let (root, disk) = verify_data()?;
        disk.sync_all()?;
        capture::publish(Path::new("/run/fvca"), "guest-clean-stop", &capture::stop_receipt(&root, &disk)?)?;
    }
    Ok(())
}

fn stop(connection: &Connection, events: &EventLoop) -> io::Result<bool> {
    let Some(domain) = connection.lookup(UUID)? else { return Ok(false); };
    invalidate_receipt()?;
    domain.shutdown(events, Duration::from_secs(28))?;
    if Path::new(PID).try_exists()? {
        return Err(invalid("the Service Guest QEMU PID file still exists after shutdown"));
    }
    println!("FVCA_SERVICE_GUEST_STOPPED");
    Ok(true)
}

fn release(connection: &Connection) -> io::Result<()> {
    if connection.lookup(UUID)?.is_some() || Path::new(PID).try_exists()? {
        return Err(invalid("the Service Guest still owns its data attachment"));
    }
    if Path::new(ALIAS).try_exists()? {
        let mounted = Command::new("/usr/bin/findmnt").env_clear()
            .args(["--mountpoint", ALIAS]).stdout(Stdio::null()).status()?;
        match mounted.code() {
            Some(0) => run(Command::new("/usr/bin/umount").args(["--internal-only", ALIAS]))?,
            Some(1) => {}
            _ => return Err(io::Error::other("could not inspect the Guest data attachment")),
        }
        fs::remove_file(ALIAS)?;
    }
    reclaim_attachment()
}

fn activate() -> io::Result<()> {
    fvca_allocator_binding::require_allocator()?;
    match std::env::args().skip(1).collect::<Vec<_>>().as_slice() {
        [] => {
            let _capture = capture::wait_for_lease(Path::new(CAPTURE_LOCK))?;
            let _lease = capture::lease(Path::new(OPERATION_LOCK))?;
            capture::live::require_idle()?;
            launch()
        }
        [option] if option == "--shutdown" => {
            let _lease = capture::lease(Path::new(OPERATION_LOCK))?;
            capture::live::require_idle()?;
            guest_trial::require_idle()?;
            shutdown()
        }
        [option] if option == "--activate-hypervisor-trial" => update::activate(false),
        [option] if option == "--return-healthy-hypervisor" => update::activate(true),
        [option] if option == "--recover-hypervisor-activation" => update::recover(),
        [option, transaction, offer] if option == "--drain-for-firmware" => {
            update::drain_firmware(transaction, offer)
        }
        [option] if option == "--activate-guest-trial" => guest_trial::activate(),
        [option] if option == "--boot-guest-trial" => guest_trial::boot_attempt(),
        [option] if option == "--recover-guest-trial" => guest_trial::recover(),
        [option] if option == "--verify-staged-guest-trial" => {
            let _capture = capture::lease(Path::new(CAPTURE_LOCK))?;
            let _lease = capture::lease(Path::new(OPERATION_LOCK))?;
            guest_trial::verify()
        }
        [option] if option == "--release" => {
            let _lease = capture::lease(Path::new(OPERATION_LOCK))?;
            capture::live::require_idle()?;
            guest_trial::require_idle()?;
            if !Path::new(ALIAS).try_exists()? && !Path::new(VM_PARENT).join(ATTACHMENT).try_exists()? {
                return Ok(());
            }
            release(&Connection::connect()?)
        }
        [option, id] if option == "--capture-stopped" => capture::stopped(id, true),
        [option, id, mode] if option == "--capture-stopped" && mode == "--leave-stopped" => capture::stopped(id, false),
        [option, id] if option == "--capture-live" => capture::live::capture(id),
        [option, id] if option == "--live-window" => capture::live::capture_window(id),
        [option, id] if option == "--recover-live" => capture::live::recover(id),
        [option, request] if option == "--restore" => capture::restore::cold_restore(request, false),
        [option, request] if option == "--restore-s3" => capture::restore::cold_restore(request, true),
        [option, id] if option == "--backup-live" => capture::backup::upload(id, true),
        [option, id] if option == "--backup-stopped" => capture::backup::upload(id, false),
        [option] if option == "--backup-job-run" => capture::backup_job::operate(true),
        [option] if option == "--backup-job-health" => capture::backup_job::operate(false),
        [option] if option == "--capture-list" => capture::retention::inspect(None),
        [option, id] if option == "--capture-inspect" => capture::retention::inspect(Some(id)),
        [option, id] if option == "--capture-expire" => capture::retention::maintain(Some(id)),
        [option] if option == "--capture-retention" => capture::retention::maintain(None),
        _ => Err(invalid("unsupported Service Guest operation")),
    }
}

fn main() -> ExitCode {
    if let Err(error) = activate() {
        eprintln!("FVCA Service Guest operation failed: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
