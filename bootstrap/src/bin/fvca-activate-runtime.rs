#![forbid(unsafe_code)]

use std::alloc::System;
use std::fs;
use std::io;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;
use std::process::{Command, ExitCode};

use fvca_initrd_bootstrap::runtime::{self, Runtime, hash};
use fvca_initrd_bootstrap::{
    HYPERVISOR_EPOCH_ARGUMENT, backup_job, backup_policy, guest_boot, host_update,
    hypervisor_slot::Slot, hypervisor_trial, invalid, recovery, retention_policy, run,
};

#[path = "fvca-activate-runtime/storage.rs"]
mod storage;

#[global_allocator]
static ALLOCATOR: System = System;

const PROBE: &str = include_str!("../../../tests/fvca-vm-runtime-probe.service");

fn activate() -> io::Result<()> {
    fvca_allocator_binding::require_allocator()?;
    if fs::read_to_string("/sys/module/kvm_intel/parameters/nested")?.trim_end() != "N"
        || !fs::metadata("/dev/kvm")?.file_type().is_char_device()
    {
        return Err(invalid(
            "Intel KVM must be available with nested virtualization disabled",
        ));
    }
    let slot = Slot::load()?;
    let protected_epoch = Path::new("/usr/lib/fvca/hypervisor-epoch").try_exists()?;
    let cmdline = fs::read_to_string("/proc/cmdline")?;
    hypervisor_trial::verify_standing_key(&cmdline)?;
    let mut epochs = cmdline
        .split_ascii_whitespace()
        .filter(|arg| arg.split('=').next() == Some(HYPERVISOR_EPOCH_ARGUMENT));
    let epoch = epochs.next();
    if epochs.next().is_some() || epoch.is_some() != protected_epoch {
        return Err(invalid(
            "expected exactly one command-line epoch with the signed Hypervisor epoch policy",
        ));
    }
    if let Some(epoch) = epoch {
        if slot.is_none() {
            return Err(invalid(
                "a protected Hypervisor epoch requires a verified GPT slot",
            ));
        }
        run(Command::new("/usr/lib/fvca/check-hypervisor-epoch").arg(epoch))?;
    }
    let verified_runtime = runtime::activate(Runtime::Vm, slot.as_ref().map(|slot| &slot.runtime))?;
    runtime::install_development_probe("fvca-vm-runtime-probe.service", PROBE)?;
    storage::activate_if_selected(protected_epoch)?;
    backup_policy::activate_if_selected()?;
    retention_policy::activate_if_selected()?;
    let recovering = recovery::activate_if_selected()?;
    backup_job::activate_if_selected(recovering)?;
    let guest =
        guest_boot::activate_if_selected(!recovering, slot.as_ref().map(|slot| &slot.guest))?;
    let esp = slot.as_ref().map(|slot| slot.esp.as_str());
    hypervisor_trial::start_candidate(
        &cmdline,
        slot.as_ref(),
        guest.as_deref(),
        &verified_runtime,
        recovering,
        epoch,
    )?;
    match hypervisor_trial::arm_if_authorized(esp, guest.as_deref(), &verified_runtime, epoch) {
        Ok(hypervisor_trial::ArmOutcome::RebootIntoTrial) => {
            return hypervisor_trial::reboot_into_trial();
        }
        Ok(hypervisor_trial::ArmOutcome::ContinueBoot) => (),
        Err(error) => eprintln!("FVCA_TRIAL_REFUSED {error}"),
    }
    if !recovering && let (Some(esp), Some(guest), Some(epoch)) = (esp, guest.as_deref(), epoch) {
        hypervisor_trial::publish_running_context(esp, &verified_runtime, guest, epoch)?;
        host_update::activate_if_selected()?;
    }

    println!("FVCA_VM_RUNTIME_ACTIVE {}", verified_runtime.extension);
    Ok(())
}

fn main() -> ExitCode {
    if let Err(error) = activate() {
        eprintln!("FVCA VM runtime activation failed: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
