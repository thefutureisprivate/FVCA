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
    let cmdline = fs::read_to_string("/proc/cmdline")?;
    hypervisor_trial::arm_candidate_watchdog(&cmdline)?;
    if fs::read_to_string("/sys/module/kvm_intel/parameters/nested")?.trim_end() != "N"
        || !fs::metadata("/dev/kvm")?.file_type().is_char_device()
    {
        return Err(invalid(
            "Intel KVM must be available with nested virtualization disabled",
        ));
    }
    let slot = Slot::load()?;
    let protected_epoch = Path::new("/usr/lib/fvca/hypervisor-epoch").try_exists()?;
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
    let storage = storage::activate_if_selected(protected_epoch)?;
    let esp = slot.as_ref().map(|slot| slot.esp.as_str());
    let enroll_firmware = |recovery| {
        if let (Some(esp), Some(epoch), Some(storage)) = (esp, epoch, &storage) {
            return host_update::activate_firmware_if_selected(
                esp,
                epoch,
                &verified_runtime,
                &storage.filesystem,
                &storage.policy_sha256,
                recovery,
            );
        }
        Ok(false)
    };
    let firmware_pending = fvca_trial_authorization::firmware::activation_pending()?;
    if firmware_pending {
        hypervisor_trial::stop_candidate_watchdog_for_firmware(&cmdline)?;
        println!("FVCA_HOST_FIRMWARE_RECOVERY_REQUIRED");
        if !enroll_firmware(true)? {
            println!("FVCA_VM_RUNTIME_ACTIVE {}", verified_runtime.extension);
            return Ok(());
        }
    }
    backup_policy::activate_if_selected()?;
    retention_policy::activate_if_selected()?;
    let recovering = !firmware_pending && recovery::activate_if_selected()?;
    backup_job::activate_if_selected(recovering)?;
    let startup = if firmware_pending {
        guest_boot::Startup::AfterFirmwareRecovery
    } else if recovering {
        guest_boot::Startup::Disabled
    } else {
        guest_boot::Startup::Automatic
    };
    let guest = guest_boot::activate_if_selected(startup, slot.as_ref().map(|slot| &slot.guest))?;
    if !firmware_pending {
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
    }
    if !recovering && let (Some(esp), Some(guest), Some(epoch)) = (esp, guest.as_deref(), epoch) {
        hypervisor_trial::publish_running_context(esp, &verified_runtime, guest, epoch)?;
        host_update::activate_if_selected()?;
    }
    if !recovering && !Path::new("/run/fvca/boot-trial-started").try_exists()? {
        if guest.is_some() {
            host_update::activate_guest_if_selected()?;
        }
        if !firmware_pending {
            enroll_firmware(false)?;
        }
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
