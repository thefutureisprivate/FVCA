#![forbid(unsafe_code)]

use std::alloc::System;
use std::ffi::{CStr, CString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use fvca_initrd_bootstrap::{guest_boot, invalid, run, vm_confinement};
use fvca_libvirt_boundary::{Connection, Domain, EventLoop, PAUSED, RUNNING};

#[global_allocator]
static ALLOCATOR: System = System;

const UUID: &CStr = c"e629aa43-af11-47c6-aedc-a2dc47f1cc3a";
const POOL: &str = "/run/fvca/host-data";
const VM_DIRECTORY: &str = "/run/fvca/host-data/vms/service-guest";
const DISK: &str = "/run/fvca/host-data/vms/service-guest/data.raw";
const ALIAS: &str = "/run/fvca/guest-state.raw";
const PID: &str = "/run/libvirt/qemu/fvca-service-guest.pid";

fn verified_definition(selection: &guest_boot::Selection<'_>) -> io::Result<CString> {
    run(Command::new("/usr/bin/findmnt").args([
        "--mountpoint", guest_boot::BOOT, "--source", "/dev/mapper/fvca-guest-boot",
        "--types", "erofs", "--options", "ro,nodev,nosuid,noexec",
    ]).stdout(Stdio::null()))?;
    let mut checksum = Command::new("/usr/bin/sha256sum").env_clear()
        .current_dir(guest_boot::BOOT)
        .args(["--strict", "--check", "--status", "-"])
        .stdin(Stdio::piped()).spawn()?;
    let written = checksum.stdin.take().expect("checksum input is piped").write_all(selection.checksums.as_bytes());
    let status = checksum.wait()?;
    written?;
    if !status.success() {
        return Err(invalid("Guest boot files differ from the UKI-authorized selection"));
    }
    let xml = fs::read(Path::new(guest_boot::BOOT).join("domain.xml"))
        .map_err(|error| io::Error::other(format!("could not read the authorized machine definition: {error}")))?;
    CString::new(xml).map_err(io::Error::other)
}

fn prepare_data() -> io::Result<()> {
    run(Command::new("/usr/bin/findmnt").args([
        "--mountpoint", POOL, "--types", "btrfs", "--options", "rw,nodev,nosuid,noexec",
    ]).stdout(Stdio::null()))?;
    for path in [POOL, "/run/fvca/host-data/vms", VM_DIRECTORY] {
        let directory = fs::symlink_metadata(path)?;
        if !directory.is_dir() || directory.uid() != 0 || directory.gid() != 0 || directory.mode() & 0o7777 != 0o700 {
            return Err(invalid("the Guest storage directory must be private and owned by root"));
        }
    }
    let root = File::open(VM_DIRECTORY)?;
    if root.metadata()?.ino() != 256 {
        return Err(invalid("Guest storage must use one Btrfs subvolume"));
    }
    let entries = fs::read_dir(VM_DIRECTORY)?.map(|entry| entry.map(|entry| entry.file_name())).collect::<io::Result<Vec<_>>>()?;
    if entries != ["data.raw"] {
        return Err(invalid("unexpected persistent files in the registered Guest subvolume"));
    }
    let metadata = fs::symlink_metadata(DISK)?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.uid() != 0 || metadata.gid() != 0
        || metadata.mode() & 0o7777 != 0o600 || metadata.len() == 0 || !metadata.len().is_multiple_of(512)
    {
        return Err(invalid("Guest data must be a private, sector-aligned raw file"));
    }
    let mount = Command::new("/usr/bin/findmnt").env_clear()
        .args(["--target", DISK, "--noheadings", "--raw", "--output", "TARGET"])
        .output()?;
    if !mount.status.success() || mount.stdout != format!("{POOL}\n").as_bytes() {
        return Err(invalid("Guest data must reside in the authorized Host pool"));
    }
    fvca_btrfs_boundary::require_cow_and_checksums(&root)?;
    fvca_btrfs_boundary::require_cow_and_checksums(&File::open(DISK)?)?;

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
    let xml = verified_definition(&selection)?;
    let events = EventLoop::register()?;
    let connection = Connection::connect()?;
    if connection.lookup(UUID)?.is_some() {
        return Err(invalid("the registered Guest already exists"));
    }
    prepare_data().map_err(|error| io::Error::other(format!("Guest data preparation failed: {error}")))?;
    let domain = connection.start_registered(&xml)?;
    if let Err(error) = wait_for_boot(&domain, selection.runtime, &events) {
        if let Err(cleanup) = domain.destroy() {
            eprintln!("FVCA could not stop the failed Guest: {cleanup}");
        }
        return Err(error);
    }
    println!("FVCA_SERVICE_GUEST_READY {} {}", selection.core, selection.runtime);
    Ok(())
}

fn shutdown() -> io::Result<()> {
    let connection = Connection::connect()?;
    let Some(domain) = connection.lookup(UUID)? else { return Ok(()); };
    domain.shutdown()?;
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if !domain.is_active()? {
            println!("FVCA_SERVICE_GUEST_STOPPED");
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err(io::Error::new(io::ErrorKind::TimedOut, "the Service Guest did not shut down cleanly"))
}

fn release() -> io::Result<()> {
    if !Path::new(ALIAS).try_exists()? {
        return Ok(());
    }
    let connection = Connection::connect()?;
    if connection.lookup(UUID)?.is_some() {
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
        [] => launch(),
        [option] if option == "--shutdown" => shutdown(),
        [option] if option == "--release" => release(),
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
