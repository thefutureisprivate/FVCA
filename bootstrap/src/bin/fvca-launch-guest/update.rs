//! Keep the Guest and its writable attachment fenced across a planned Host reboot.

use std::fs::{self, File};
use std::io;
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use fvca_initrd_bootstrap::{
    guest_boot,
    hypervisor_trial::{healthy_return, online::PendingTrial, queue_host_reboot},
    run,
};
use fvca_libvirt_boundary::{Connection, RUNNING};
use fvca_trial_authorization::firmware::{self, DRAIN_RECEIPT, RUN_DIRECTORY};
use fvca_trial_authorization::security_force_stop;

use super::{
    ALIAS, ATTACHMENT, CAPTURE_LOCK, DISK, OPERATION_LOCK, PID, POOL, RECEIPT, UUID, VM_PARENT,
    attachment_record, capture, guest_trial, invalid, invalidate_receipt, private_directory,
    raw_disk_metadata, release, shutdown, verify_data, verify_pool, verify_storage_directory,
};

const RUN: &str = "/run/fvca";
const FENCE: &str = "hypervisor-activation";
const GUEST_UNIT: &str = "fvca-service-guest.service";

pub(super) fn require_idle() -> io::Result<()> {
    if Path::new(RUN).join(FENCE).try_exists()? {
        return Err(io::Error::other(
            "Hypervisor activation owns the Guest operation lease",
        ));
    }
    Ok(())
}

pub(super) fn activate(returning: bool) -> io::Result<()> {
    let _capture = capture::lease(Path::new(CAPTURE_LOCK))?;
    let _operation = capture::lease(Path::new(OPERATION_LOCK))?;
    capture::live::require_idle()?;
    capture::restore::require_idle()?;
    verify_pool()?;
    let pending = (!returning).then(PendingTrial::verify).transpose()?;
    let (transaction, deadline) = match &pending {
        Some(pending) => (pending.transaction().to_owned(), pending.force_stop_after()),
        None => healthy_return()?,
    };
    if deadline.is_some() && !security_force_stop(&fs::read_to_string("/proc/cmdline")?)? {
        return Err(invalid("the verified boot does not authorize a security force-stop"));
    }
    let recheck = || {
        if let Some(pending) = &pending {
            return pending.recheck();
        }
        let (current, current_deadline) = healthy_return()?;
        if current != transaction || current_deadline != deadline {
            return Err(invalid("healthy trial changed during Guest shutdown"));
        }
        Ok(())
    };
    let connection = Connection::connect()?;
    let running = running_guest(&connection, deadline_reached(deadline)?)?;
    capture::publish(
        Path::new(RUN),
        FENCE,
        if running { "running\n" } else { "stopped\n" },
    )?;
    if running {
        match shutdown() {
            Ok(()) => require_clean_stop()?,
            Err(error) => {
                let Some(deadline) = deadline.filter(|_| error.kind() == io::ErrorKind::TimedOut) else {
                    return Err(error);
                };
                if !deadline_reached(Some(deadline))? {
                    return Err(error);
                }
                force_stop(&connection, &transaction, deadline, &recheck)?;
            }
        }
    }
    require_drained(Some(&connection))?;
    recheck()?;
    if returning {
        println!("FVCA_HYPERVISOR_PROMOTION_DRAINED {transaction}");
    } else {
        println!("FVCA_HYPERVISOR_TRIAL_DRAINED {transaction}");
    }
    queue_host_reboot()
}

fn deadline_reached(deadline: Option<u64>) -> io::Result<bool> {
    deadline.map_or(Ok(false), |deadline| {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?;
        Ok(now.as_secs() >= deadline)
    })
}

fn running_guest(connection: &Connection, force_due: bool) -> io::Result<bool> {
    match connection.lookup(UUID)? {
        // The lifecycle leases and the live-capture fence cover Host-managed
        // freezes. Once force is due, an unavailable agent cannot veto drain.
        Some(guest) if guest.state()? == RUNNING && (force_due || !guest.guest_frozen()?) => Ok(true),
        Some(_) => Err(invalid(
            "Host activation requires a running and thawed Guest",
        )),
        None => Ok(false),
    }
}

fn force_stop(
    connection: &Connection,
    transaction: &str,
    deadline: u64,
    recheck: impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    let guest = connection
        .lookup(UUID)?
        .ok_or_else(|| invalid("Guest exited before the forced stop"))?;
    if guest.state()? != RUNNING {
        return Err(invalid("forced stop requires the running registered Guest"));
    }
    let selection = fs::read_to_string(guest_boot::SELECTION)?;
    let bundle = guest_boot::parse(&selection)?.bundle;
    let instance = capture::live::require_instance(bundle)?;
    let root = verify_storage_directory()?;
    // The sVirt label reserves access to the running disk for its QEMU domain.
    let source = raw_disk_metadata(Path::new(DISK))?;
    let alias = raw_disk_metadata(Path::new(ALIAS))?;
    let attachment = attachment_record(&root, &source)?;
    if (source.dev(), source.ino()) != (alias.dev(), alias.ino())
        || capture::optional_record(&Path::new(VM_PARENT).join(ATTACHMENT))?.as_deref() != Some(&attachment)
    {
        return Err(invalid("the running Guest does not own the registered disk attachment"));
    }
    let directory = Path::new(POOL).join("boot-trials");
    private_directory(&directory)?;
    let name = format!("{transaction}.forced-stop-{}", instance.trim_end().replace(':', "-"));
    let record = format!(
        "FVCA-HYPERVISOR-FORCED-STOP-1\ntransaction={transaction}\ninstance={instance}\
         security_deadline={deadline}\nguest_bundle={bundle}\nrequested_consistency=crash-consistent\n{attachment}",
    );
    invalidate_receipt()?;
    capture::publish(&directory, &format!("{name}.intent"), &record)?;
    recheck()?;
    if !deadline_reached(Some(deadline))? {
        return Err(invalid("security deadline is no longer due"));
    }
    if guest.state()? != RUNNING || capture::live::require_instance(bundle)? != instance {
        return Err(invalid("the Guest instance changed before the forced stop"));
    }
    guest.destroy()?;
    release(connection)?;
    require_drained(Some(connection))?;
    let (root, disk) = verify_data()?;
    if attachment_record(&root, &disk.metadata()?)? != attachment {
        return Err(invalid("the released disk no longer matches the forced-stop intent"));
    }
    disk.sync_all()?;
    capture::publish(
        &directory,
        &name,
        &format!("{record}achieved_consistency=crash-consistent\n"),
    )?;
    println!("FVCA_HYPERVISOR_GUEST_FORCED_STOP {transaction} crash-consistent");
    Ok(())
}

fn require_clean_stop() -> io::Result<()> {
    let (root, disk) = verify_data()?;
    if capture::optional_record(Path::new(RECEIPT))? != Some(capture::stop_receipt(&root, &disk)?) {
        return Err(invalid(
            "the Guest disk has no matching orderly shutdown receipt",
        ));
    }
    Ok(())
}

fn require_drained(connection: Option<&Connection>) -> io::Result<()> {
    if let Some(connection) = connection
        && connection.lookup(UUID)?.is_some()
    {
        return Err(invalid("the Guest is still active"));
    }
    if Path::new(PID).try_exists()?
        || Path::new(ALIAS).try_exists()?
        || Path::new(VM_PARENT).join(ATTACHMENT).try_exists()?
    {
        return Err(invalid("the Guest disk attachment is still active"));
    }
    Ok(())
}

pub(super) fn verify_firmware_drain(transaction: &str, offer: &str) -> io::Result<()> {
    let lease = File::from(io::stdin().as_fd().try_clone_to_owned()?);
    capture::require_inherited_lifecycle_lease(&lease)?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let receipt = firmware::drain_receipt(boot.trim_end(), transaction, offer)?;
    let _operation = capture::lock_existing_operation()?;
    require_idle()?;
    guest_trial::require_idle()?;
    capture::live::require_idle()?;
    capture::restore::require_idle()?;
    if !firmware::activation_pending()? {
        return Err(invalid(
            "firmware drain requires a durable activation fence",
        ));
    }
    let pool = verify_pool()?;
    let selected = Path::new(guest_boot::SELECTION).try_exists()?;
    let connection = if selected || Path::new(fvca_libvirt_boundary::LOCAL_SOCKET).try_exists()? {
        Some(Connection::connect()?)
    } else {
        None
    };
    require_drained(connection.as_ref())?;
    if selected {
        require_clean_stop()?;
    }
    fvca_btrfs_boundary::sync(&pool)?;
    let directory = Path::new(RUN_DIRECTORY);
    capture::replace_record(directory, DRAIN_RECEIPT, &receipt)?;
    run(Command::new("/usr/bin/chcon")
        .args([
            "--no-dereference",
            "system_u:object_r:fvca_firmware_drain_t:s0",
        ])
        .arg(directory.join(DRAIN_RECEIPT)))?;
    println!("FVCA_FIRMWARE_GUEST_DRAINED {transaction}");
    Ok(())
}

pub(super) fn recover() -> io::Result<()> {
    let fence = Path::new(RUN).join(FENCE);
    let restart = {
        let _capture = capture::lease_for_activation_recovery()?;
        let restart = recover_attachment(&fence)?;
        if restart {
            // Queue while launches still wait on the capture lease. If systemd
            // refuses the restart, preserve the fence for recovery to retry.
            run(Command::new("/usr/bin/systemctl").args(["--no-block", "restart", GUEST_UNIT]))?;
        }
        match fs::remove_file(&fence) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            result => result?,
        }
        restart
    };
    if restart {
        run(Command::new("/usr/bin/systemctl").args(["start", GUEST_UNIT]))?;
    }
    println!("FVCA_HYPERVISOR_ACTIVATION_RECOVERED");
    Ok(())
}

fn recover_attachment(fence: &Path) -> io::Result<bool> {
    let _operation = capture::lease(Path::new(OPERATION_LOCK))?;
    let Some(state) = capture::optional_record(fence)? else {
        return Ok(false);
    };
    let connection = Connection::connect()?;
    let restart = match (state.as_str(), connection.lookup(UUID)?) {
        ("stopped\n", None) => false,
        ("running\n", None) => {
            release(&connection)?;
            true
        }
        ("running\n", Some(guest)) if guest.state()? == RUNNING && !guest.guest_frozen()? => false,
        _ => {
            return Err(invalid(
                "the Guest state after interrupted Hypervisor activation is uncertain",
            ));
        }
    };
    Ok(restart)
}
