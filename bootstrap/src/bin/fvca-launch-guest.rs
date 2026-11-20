#![forbid(unsafe_code)]

use std::alloc::System;
use std::ffi::{CStr, CString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use fvca_initrd_bootstrap::{guest_boot, invalid, run, vm_confinement};
use fvca_libvirt_boundary::{Connection, Domain, EventLoop, PAUSED, RUNNING};

#[path = "fvca-launch-guest/capture.rs"]
mod capture;

#[global_allocator]
static ALLOCATOR: System = System;

const UUID: &CStr = c"e629aa43-af11-47c6-aedc-a2dc47f1cc3a";
const POOL: &str = "/run/fvca/host-data";
const VM_DIRECTORY: &str = "/run/fvca/host-data/vms/service-guest";
const DISK: &str = "/run/fvca/host-data/vms/service-guest/data.raw";
const ALIAS: &str = "/run/fvca/guest-state.raw";
const PID: &str = "/run/libvirt/qemu/fvca-service-guest.pid";
const RECEIPT: &str = "/run/fvca/guest-clean-stop";
const OPERATION_LOCK: &str = "/run/fvca/guest-operation.lock";
const CAPTURE_LOCK: &str = "/run/fvca/guest-capture.lock";

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
    run(Command::new("/usr/bin/findmnt").args([
        "--mountpoint", guest_boot::BOOT, "--source", "/dev/mapper/fvca-guest-boot",
        "--types", "erofs", "--options", "ro,nodev,nosuid,noexec",
    ]).stdout(Stdio::null()))?;
    let boot = Path::new(guest_boot::BOOT);
    verify_boot_files(boot, selection)?;
    let xml = fs::read(boot.join("domain.xml"))
        .map_err(|error| io::Error::other(format!("could not read the authorized machine definition: {error}")))?;
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
    for path in ["/run/fvca/host-data/vms", VM_DIRECTORY] {
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
    let mount = Command::new("/usr/bin/findmnt").env_clear()
        .args(["--target", DISK, "--noheadings", "--raw", "--output", "TARGET"])
        .output()?;
    if !mount.status.success() || mount.stdout != format!("{POOL}\n").as_bytes() {
        return Err(invalid("Guest data must reside in the authorized Host pool"));
    }
    fvca_btrfs_boundary::require_cow_and_checksums(&root)?;
    Ok(root)
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

fn prepare_data() -> io::Result<()> {
    verify_data()?;
    invalidate_receipt()?;
    // Keep the pool private while giving sVirt one file to label for QEMU.
    run(Command::new("/usr/bin/chcon").args(["system_u:object_r:virt_image_t:s0", DISK]))?;
    OpenOptions::new().write(true).create_new(true).mode(0o600).open(ALIAS)?;
    run(Command::new("/usr/bin/mount").args(["--internal-only", "--bind", DISK, ALIAS]))
}

fn wait_for_boot(domain: &Domain<'_>, runtime: &str, events: &EventLoop) -> io::Result<()> {
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
    let deadline = Instant::now() + Duration::from_secs(75);
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
        if tail.windows(16).any(|bytes| bytes == b"FVCA_BOOT_FAILED") {
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
    let payload = fs::read_to_string(guest_boot::SELECTION)?;
    let selection = guest_boot::parse(&payload)?;
    capture::restore::authorize_launch(selection.bundle)?;
    let xml = verified_definition(&selection)?;
    let events = EventLoop::register()?;
    let connection = Connection::connect()?;
    start(&connection, &events, &selection, &xml)
}

fn start(connection: &Connection, events: &EventLoop, selection: &guest_boot::Selection<'_>, xml: &CStr) -> io::Result<()> {
    if connection.lookup(UUID)?.is_some() {
        return Err(invalid("the registered Guest already exists"));
    }
    prepare_data().map_err(|error| io::Error::other(format!("Guest data preparation failed: {error}")))?;
    let domain = connection.start_registered(xml)?;
    if let Err(error) = wait_for_boot(&domain, selection.runtime, events)
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
        run(Command::new("/usr/bin/chcon").args(["--no-dereference", "system_u:object_r:fvca_host_data_t:s0", DISK]))?;
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
    if !Path::new(ALIAS).try_exists()? {
        return Ok(());
    }
    if connection.lookup(UUID)?.is_some() || Path::new(PID).try_exists()? {
        return Err(invalid("the Service Guest still owns its data attachment"));
    }
    let mounted = Command::new("/usr/bin/findmnt").env_clear()
        .args(["--mountpoint", ALIAS]).stdout(Stdio::null()).status()?;
    match mounted.code() {
        Some(0) => run(Command::new("/usr/bin/umount").args(["--internal-only", ALIAS]))?,
        Some(1) => {}
        _ => return Err(io::Error::other("could not inspect the Guest data attachment")),
    }
    fs::remove_file(ALIAS)
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
            shutdown()
        }
        [option] if option == "--release" => {
            let _lease = capture::lease(Path::new(OPERATION_LOCK))?;
            capture::live::require_idle()?;
            if !Path::new(ALIAS).try_exists()? {
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
