//! Prepare the one writable ESP view and exec the fixed native writer.

use std::fs::TryLockError;
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

use fvca_trial_authorization::firmware::{DRAIN_RECEIPT, drain_receipt};
use rustix::mount::{MountPropagationFlags, mount_change};
use rustix::thread::{
    CapabilitySet, CapabilitySets, UnshareFlags, capabilities, clear_ambient_capability_set,
    no_new_privs, remove_capability_from_bounding_set, set_capabilities, unshare_unsafe,
};

use super::{activation::Activation, boot, boot_id, capsule, enrolled_host};
use crate::{Result, handoff, invalid, state};

const SETUP: CapabilitySet = CapabilitySet::SYS_ADMIN.union(CapabilitySet::SETPCAP);
const WRITER_STATE: &str = "/run/fvca-firmware-writer";

pub(crate) fn serve() -> Result<()> {
    let notify = std::env::var_os("NOTIFY_SOCKET")
        .ok_or_else(|| invalid("firmware writer requires its supervised service"))?;
    require_setup_privileges()?;
    boot::require_enforced_boot()?;
    let (boot, _, pool) = enrolled_host()?;
    match handoff::install_lease()?.try_lock() {
        Err(TryLockError::WouldBlock) => (),
        Err(error) => return Err(error.into()),
        Ok(()) => {
            return Err(invalid("firmware writer requires the held Host lifecycle lease").into());
        }
    }
    let operation = Activation::writer_operation(&pool, &boot_id()?)?;
    let receipt = state::open_regular(&boot.join(DRAIN_RECEIPT))?;
    handoff::private_file(&receipt)?;
    let expected = drain_receipt(
        &operation.boot_id,
        &operation.transaction,
        &operation.offer_sha256,
    )?;
    let mut actual = Vec::new();
    receipt
        .take(expected.len() as u64 + 1)
        .read_to_end(&mut actual)?;
    if actual != expected.as_bytes() {
        return Err(invalid("firmware writer requires the current Guest drain receipt").into());
    }
    // This separates the mount tree without unsharing file descriptors.
    unsafe { unshare_unsafe(UnshareFlags::NEWNS) }?;
    mount_change(
        Path::new("/"),
        MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
    )?;
    capsule::prepare_writer_mount()?;
    drop_setup_privileges()?;
    Err(Command::new("/usr/libexec/fwupd/fwupd")
        .env_clear()
        .env("NOTIFY_SOCKET", notify)
        .env(
            "DBUS_SYSTEM_BUS_ADDRESS",
            "unix:path=/run/fvca/firmware-bus-writer",
        )
        .env("STATE_DIRECTORY", WRITER_STATE)
        .env("CACHE_DIRECTORY", WRITER_STATE)
        .env("FVCA_FWUPD_PERSISTENT_HISTORY", "1")
        .env("FVCA_FWUPD_CAPSULE_WRITER", "1")
        .exec()
        .into())
}

fn require_setup_privileges() -> Result<()> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let bound = status
        .lines()
        .find_map(|line| line.strip_prefix("CapBnd:"))
        .and_then(|value| u64::from_str_radix(value.trim(), 16).ok());
    let current = capabilities(None)?;
    if !no_new_privs()? || bound != Some(SETUP.bits()) || current.effective != SETUP {
        return Err(invalid("firmware writer has unexpected mount setup privileges").into());
    }
    Ok(())
}

fn drop_setup_privileges() -> Result<()> {
    remove_capability_from_bounding_set(CapabilitySet::SYS_ADMIN)?;
    remove_capability_from_bounding_set(CapabilitySet::SETPCAP)?;
    clear_ambient_capability_set()?;
    let empty = CapabilitySet::empty();
    set_capabilities(
        None,
        CapabilitySets {
            effective: empty,
            permitted: empty,
            inheritable: empty,
        },
    )?;
    Ok(())
}
