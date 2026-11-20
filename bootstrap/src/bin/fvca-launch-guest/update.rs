//! Keep the Guest and its writable attachment fenced across a planned Host reboot.

use std::fs::{self, File};
use std::io;
use std::os::fd::AsFd;
use std::path::Path;
use std::process::Command;

use fvca_initrd_bootstrap::{
    guest_boot,
    hypervisor_trial::{healthy_return, online::PendingTrial, queue_host_reboot},
    run,
};
use fvca_libvirt_boundary::{Connection, RUNNING};
use fvca_trial_authorization::firmware::{self, DRAIN_RECEIPT, RUN_DIRECTORY};

use super::{
    ALIAS, ATTACHMENT, CAPTURE_LOCK, OPERATION_LOCK, PID, RECEIPT, UUID, VM_PARENT, capture,
    guest_trial, invalid, release, shutdown, verify_data, verify_pool,
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
    let transaction = match &pending {
        Some(pending) => pending.transaction().to_owned(),
        None => healthy_return()?,
    };
    let connection = Connection::connect()?;
    let running = running_guest(&connection)?;
    capture::publish(
        Path::new(RUN),
        FENCE,
        if running { "running\n" } else { "stopped\n" },
    )?;
    if running {
        shutdown()?;
        require_clean_stop()?;
    }
    require_drained(Some(&connection))?;
    if let Some(pending) = pending {
        pending.recheck()?;
        println!("FVCA_HYPERVISOR_TRIAL_DRAINED {transaction}");
    } else {
        if healthy_return()? != transaction {
            return Err(invalid("healthy trial changed during Guest shutdown"));
        }
        println!("FVCA_HYPERVISOR_PROMOTION_DRAINED {transaction}");
    }
    queue_host_reboot()
}

fn running_guest(connection: &Connection) -> io::Result<bool> {
    match connection.lookup(UUID)? {
        Some(guest) if guest.state()? == RUNNING && !guest.guest_frozen()? => Ok(true),
        Some(_) => Err(invalid(
            "Host activation requires a running and thawed Guest",
        )),
        None => Ok(false),
    }
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
