#![forbid(unsafe_code)]

use std::alloc::System;
use std::fs;
use std::io;
use std::os::unix::fs::FileTypeExt;
use std::process::ExitCode;

use fvca_initrd_bootstrap::{backup_job, backup_policy, guest_boot, hypervisor_slot::Slot, hypervisor_trial, invalid, recovery, retention_policy};
use fvca_initrd_bootstrap::runtime::{self, Runtime, hash};

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
        return Err(invalid("Intel KVM must be available with nested virtualization disabled"));
    }
    let slot = Slot::load()?;
    let verified_runtime = runtime::activate(Runtime::Vm, slot.as_ref().map(|slot| &slot.runtime))?;
    runtime::install_development_probe("fvca-vm-runtime-probe.service", PROBE)?;
    storage::activate_if_selected()?;
    backup_policy::activate_if_selected()?;
    retention_policy::activate_if_selected()?;
    let recovering = recovery::activate_if_selected()?;
    backup_job::activate_if_selected(recovering)?;
    let guest = guest_boot::activate_if_selected(!recovering, slot.as_ref().map(|slot| &slot.guest))?;
    let esp = slot.as_ref().map(|slot| slot.esp.as_str());
    hypervisor_trial::start_candidate(slot.as_ref(), guest.as_deref(), &verified_runtime, recovering)?;
    if let Err(error) = hypervisor_trial::arm_if_authorized(esp, guest.as_deref(), &verified_runtime) {
        eprintln!("FVCA_TRIAL_REFUSED {error}");
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
