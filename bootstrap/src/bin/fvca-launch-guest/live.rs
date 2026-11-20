//! Coordinate a recoverable manual disk barrier for the registered Service Guest.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use super::{Consistency, Store, attached_disk, btrfs, directory, finalize, guest_boot, invalid, lease,
            parse_plan, plan_text, private_directory, publish, read_record, remove_stale_stage, run,
            runtime, seal, uuid};
use crate::{CAPTURE_LOCK, OPERATION_LOCK, PID, UUID, verified_definition, verify_storage_directory};
use fvca_libvirt_boundary::{Connection, RUNNING};

const RUN: &str = "/run/fvca";
const ACTIVE: &str = "/run/fvca/guest-live-active";
const INSTANCE: &str = "/run/fvca/guest-live-instance";
const RECOVERY_LOCK: &str = "/run/fvca/guest-live-recovery.lock";

fn instance() -> io::Result<String> {
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let boot = uuid(boot.trim_end())?;
    let pid = fs::read_to_string(PID)?.trim_end().parse::<u32>().map_err(io::Error::other)?;
    if pid < 2 {
        return Err(invalid("invalid libvirt Guest PID"));
    }
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    // The comm field can contain spaces and parentheses. Field 22 follows it.
    let start = stat.rsplit_once(") ").and_then(|(_, fields)| fields.split_ascii_whitespace().nth(19))
        .ok_or_else(|| invalid("missing QEMU process start time"))?;
    let start = start.parse::<u64>().map_err(io::Error::other)?;
    Ok(format!("{boot}:{pid}:{start}\n"))
}

pub(crate) fn record_launch(bundle: &str) -> io::Result<()> {
    let bundle = runtime::hash(bundle)?;
    let vm = instance()?;
    remove_stale_stage(Path::new(INSTANCE))?;
    publish(Path::new(RUN), "guest-live-instance", &format!("{bundle}\n{vm}"))
}

pub(crate) fn require_instance(bundle: &str) -> io::Result<String> {
    let vm = instance()?;
    if read_record(Path::new(INSTANCE))? != format!("{bundle}\n{vm}") {
        return Err(invalid("the running VM does not match its verified launch receipt"));
    }
    Ok(vm)
}

fn active() -> io::Result<Option<String>> {
    match read_record(Path::new(ACTIVE)) {
        Ok(id) => Ok(Some(uuid(id.trim_end())?.to_owned())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

pub(crate) fn require_idle() -> io::Result<()> {
    if let Some(id) = active()? {
        return Err(io::Error::other(format!("live capture {id} still owns the Guest operation lease")));
    }
    Ok(())
}

pub(super) fn can_reconcile(id: &str) -> io::Result<bool> {
    if active()?.as_deref() == Some(id) {
        return Ok(true);
    }
    require_idle()?;
    match read_record(&window_path(id).join("sealed")) {
        Ok(sealed) if sealed == "1\n" => Ok(true),
        Ok(_) => Err(invalid("unexpected live seal acknowledgement")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn window_path(id: &str) -> PathBuf {
    Path::new(RUN).join(format!("live-capture-{id}"))
}

fn control(verb: &str, unit: &str) -> io::Result<()> {
    run(Command::new("/usr/bin/systemctl").args([verb, unit]))
}

fn arm(store: &Store, id: &str) -> io::Result<()> {
    let _lifecycle = lease(Path::new(OPERATION_LOCK))?;
    let _recovery = lease(Path::new(RECOVERY_LOCK))?;
    require_idle()?;
    let launch = fs::read_to_string(guest_boot::SELECTION)?;
    let selection = guest_boot::parse(&launch)?;
    verified_definition(&selection)?;
    let vm = require_instance(selection.bundle)?;
    let root = verify_storage_directory()?;
    let source = btrfs::subvolume(&root)?;
    if source.read_only {
        return Err(invalid("the live source subvolume must be writable"));
    }
    let bytes = attached_disk()?.metadata()?.len();
    let connection = Connection::connect()?;
    let domain = connection.lookup(UUID)?.ok_or_else(|| invalid("the Service Guest is stopped"))?;
    if domain.state()? != RUNNING || domain.guest_frozen()? {
        return Err(invalid("live capture requires a running and thawed Service Guest"));
    }
    domain.require_guest_agent()?;
    domain.require_guest_disk_active(true)?;
    store.prepare(&launch, bytes)?;

    let window = window_path(id);
    directory(&store.path)?;
    publish(&store.path, "intent", &plan_text(store, id, &source, bytes, &launch)?)?;
    directory(&window)?;
    publish(&window, "instance", &vm)?;
    publish(Path::new(RUN), "guest-live-active", &format!("{id}\n"))
}

pub(crate) fn capture(id: &str) -> io::Result<()> {
    uuid(id)?;
    let capture_lock = lease(Path::new(CAPTURE_LOCK))?;
    super::restore::require_idle()?;
    let store = Store::open(id, Consistency::Filesystem)?;
    store.require_available()?;
    let timer = format!("fvca-live-recover@{id}.timer");
    let recovery = format!("fvca-live-recover@{id}.service");
    if store.path.try_exists()? {
        private_directory(&store.path)?;
        if active()?.as_deref() == Some(id) {
            control("start", &recovery)?;
        }
        require_idle()?;
    } else {
        arm(&store, id)?;
        let result = control("start", &timer)
            .and_then(|()| control("start", &format!("fvca-live-window@{id}.service")));
        // A failed start or a killed coordinator can leave the independently
        // supervised recovery responsible for clearing the volatile lease.
        if active()?.as_deref() == Some(id) {
            control("start", &recovery)?;
        }
        require_idle()?;
        control("stop", &timer)?;
        result?;
    }
    // A worker killed during rename or fsync can leave a visible seal. Only
    // approve it after the worker reports the completed durability barrier.
    if !store.path.join("live-seal-verified").try_exists()? {
        let window = window_path(id);
        private_directory(&window)?;
        if read_record(&window.join("sealed"))? != "1\n" {
            return Err(invalid("live capture did not acknowledge its durable seal"));
        }
        publish(&store.path, "live-seal-verified", "1\n")?;
    }
    drop(capture_lock);
    finalize(&store, id)
}

pub(crate) fn capture_window(id: &str) -> io::Result<()> {
    uuid(id)?;
    let window = window_path(id);
    private_directory(&window)?;
    let _worker = lease(&window.join("worker.lock"))?;
    if active()?.as_deref() != Some(id) || window.join("closed").try_exists()? {
        return Err(invalid("the live capture window is closed"));
    }
    let store = Store::open(id, Consistency::Filesystem)?;
    let dest = private_directory(&store.path)?;
    let intent = read_record(&store.path.join("intent"))?;
    let plan = parse_plan(&intent, id, &store)?;
    let selection = guest_boot::parse(plan.launch)?;
    let vm = require_instance(selection.bundle)?;
    let root = verify_storage_directory()?;
    let source = btrfs::subvolume(&root)?;
    let disk = attached_disk()?;
    if vm != read_record(&window.join("instance"))? || source.read_only
        || source.uuid != plan.source || source.id != plan.source_id || disk.metadata()?.len() != plan.bytes
    {
        return Err(invalid("the live Guest or source disk changed after preparation"));
    }
    let connection = Connection::connect()?;
    let domain = connection.lookup(UUID)?.ok_or_else(|| invalid("the Service Guest is stopped"))?;
    if domain.state()? != RUNNING || domain.guest_frozen()? || window.join("closed").try_exists()? {
        return Err(invalid("the Service Guest no longer has an eligible live capture window"));
    }
    publish(&window, "freeze-issued", "1\n")?;
    domain.freeze_guest_data()?;
    publish(&window, "freeze-settled", "1\n")?;
    println!("FVCA_LIVE_GUEST_FROZEN {id}");
    publish(&window, "pause-issued", "1\n")?;
    let paused = domain.pause_for_guest_disk_capture();
    publish(&window, "pause-settled", "1\n")?;
    paused?;
    println!("FVCA_LIVE_DISK_INACTIVE {id}");
    // Opened before the barrier so fsync can report writeback errors from the window.
    disk.sync_all()?;
    let text = plan_text(&store, id, &source, plan.bytes, plan.launch)?;
    publish(&store.path, "plan", &text)?;
    btrfs::snapshot_read_only(&root, &dest, "snapshot")?;
    dest.sync_all()?;
    println!("FVCA_LIVE_SNAPSHOT_CREATED {id}");
    seal(&store, id, &text)?;
    publish(&window, "sealed", "1\n")
}

fn fence_worker(window: &Path, id: &str) -> io::Result<bool> {
    publish(window, "closed", "1\n")?;
    let lock = window.join("worker.lock");
    match lease(&lock) {
        Ok(_) => return Ok(true),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
        Err(error) => return Err(error),
    }
    let unit = format!("fvca-live-window@{id}.service");
    let signal = run(Command::new("/usr/bin/systemctl").args(["kill", "--kill-whom=main", "--signal=KILL", &unit]));
    let deadline = Instant::now() + Duration::from_millis(250);
    loop {
        match lease(&lock) {
            Ok(_) => return Ok(true),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
        if Instant::now() >= deadline {
            // A killed worker in kernel I/O can retain its lock. Recovery may
            // attempt resume, but the volatile lease must remain in this case.
            signal?;
            return Ok(false);
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn restore_guest(window: &Path, id: &str) -> io::Result<bool> {
    let connection = Connection::connect()?;
    let Some(domain) = connection.lookup(UUID)? else {
        if Path::new(PID).try_exists()? {
            return Err(invalid("the captured Service Guest PID still exists without its domain"));
        }
        return Ok(false);
    };
    if instance()? != read_record(&window.join("instance"))? {
        return Err(invalid("the Service Guest changed during live capture recovery"));
    }
    // The pinned driver's QMP query waits behind its manual snapshot job.
    let activity = domain.require_guest_disk_active(true);
    if domain.paused_for_snapshot()? {
        publish(window, "pause-settled", "1\n")?;
        domain.resume()?;
        println!("FVCA_LIVE_VM_RESUMED {id}");
    } else {
        activity?;
    }
    if domain.state()? != RUNNING {
        return Err(invalid("the captured Service Guest is not running after recovery"));
    }
    domain.require_guest_disk_active(true)?;
    // The pinned driver's agent job serializes this query against an in-flight freeze.
    if domain.guest_frozen()? {
        publish(window, "freeze-settled", "1\n")?;
        domain.thaw_guest_data()?;
        println!("FVCA_LIVE_GUEST_THAWED {id}");
    }
    domain.require_guest_agent()?;
    // A killed RPC client can leave a request queued. The matching returned
    // response or observed effect proves that request reached the provider.
    if !window.join("freeze-settled").try_exists()?
        || (window.join("pause-issued").try_exists()? && !window.join("pause-settled").try_exists()?)
    {
        return Err(invalid("the interrupted freeze or pause request has an unresolved provider outcome"));
    }
    Ok(true)
}

pub(crate) fn recover(id: &str) -> io::Result<()> {
    uuid(id)?;
    let _recovery = lease(Path::new(RECOVERY_LOCK))?;
    if active()?.as_deref() != Some(id) {
        return Ok(());
    }
    let window = window_path(id);
    private_directory(&window)?;
    let worker_stopped = fence_worker(&window, id)?;
    let guest_recovered = !window.join("freeze-issued").try_exists()? || restore_guest(&window, id)?;
    if !worker_stopped {
        return Err(invalid("the live capture worker has not exited after its deadline"));
    }
    fs::remove_file(ACTIVE)?;
    if !guest_recovered {
        return Err(invalid("the captured Service Guest exited before it could be recovered"));
    }
    println!("FVCA_LIVE_GUEST_RECOVERED {id}");
    Ok(())
}
