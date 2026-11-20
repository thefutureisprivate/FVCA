#![forbid(unsafe_code)]

use std::alloc::System;
use std::fs;
use std::io::{self, Read};
use std::os::fd::OwnedFd;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};

use fvca_initrd_bootstrap::runtime::{self, Runtime, hash};
use fvca_initrd_bootstrap::{
    HYPERVISOR_EPOCH_ARGUMENT, backup_job, backup_policy, guest_boot, host_network, host_update,
    host_workload, hypervisor_slot::Slot, hypervisor_trial, invalid, kernel_policy, recovery,
    retention_policy, run,
};

#[path = "fvca-activate-runtime/storage.rs"]
mod storage;

#[global_allocator]
static ALLOCATOR: System = System;

const PROBE: &str = include_str!("../../../tests/fvca-vm-runtime-probe.service");

fn check_epoch(epoch: &str) -> io::Result<Option<host_update::FirmwareTpm>> {
    let checker = "/usr/lib/fvca/check-hypervisor-epoch";
    if !Path::new("/usr/lib/fvca/firmware-update-owner").try_exists()? {
        run(Command::new(checker).arg(epoch))?;
        return Ok(None);
    }
    let (report, stdout) = UnixStream::pair()?;
    run(Command::new(checker)
        .args([epoch, "--measure-firmware-tpm"])
        .stdout(Stdio::from(OwnedFd::from(stdout))))?;
    let mut text = String::new();
    report.take(256).read_to_string(&mut text)?;
    let (accepted, measurement) = text
        .split_once('\n')
        .ok_or_else(|| invalid("missing accepted Hypervisor epoch"))?;
    let prefix = epoch
        .strip_prefix(HYPERVISOR_EPOCH_ARGUMENT)
        .and_then(|epoch| epoch.strip_prefix('='))
        .and_then(|epoch| epoch.split_once(','))
        .map(|(epoch, _)| format!("FVCA_HYPERVISOR_EPOCH_ACCEPTED {epoch} "))
        .ok_or_else(|| invalid("invalid measured Hypervisor epoch selection"))?;
    let floor_text = accepted
        .strip_prefix(&prefix)
        .ok_or_else(|| invalid("invalid accepted TPM release floor"))?;
    let floor = floor_text
        .parse::<u64>()
        .ok()
        .filter(|floor| *floor != 0 && floor.to_string() == floor_text)
        .ok_or_else(|| invalid("invalid accepted TPM release floor"))?;
    println!("{accepted}");
    if measurement.is_empty() {
        return Ok(None);
    }
    let pcr7 = measurement
        .strip_suffix('\n')
        .and_then(|line| line.strip_prefix("FVCA_FIRMWARE_PCR7 "))
        .ok_or_else(|| invalid("invalid firmware TPM measurement"))?;
    Ok(Some(host_update::FirmwareTpm {
        floor,
        pcr7_sha256: hash(pcr7)?.to_owned(),
    }))
}

fn activate() -> io::Result<()> {
    fvca_allocator_binding::require_allocator()?;
    let cmdline = fs::read_to_string("/proc/cmdline")?;
    hypervisor_trial::arm_candidate_watchdog(&cmdline)?;
    kernel_policy::require_signed_modules()?;
    let smt = fs::read_to_string("/sys/devices/system/cpu/smt/control")?;
    if !matches!(smt.as_str(), "forceoff\n" | "notsupported\n")
        || fs::read_to_string("/sys/devices/system/cpu/smt/active")? != "0\n"
    {
        return Err(invalid("the Hypervisor requires SMT to be disabled"));
    }
    if fs::read_to_string("/sys/module/kvm_intel/parameters/nested")?.trim_end() != "N"
        || !fs::metadata("/dev/kvm")?.file_type().is_char_device()
    {
        return Err(invalid(
            "Intel KVM must be available with nested virtualization disabled",
        ));
    }
    // Guest trials and UEFI update/recovery transactions use these after switch-root.
    kernel_policy::load_modules(&["loop", "vfat", "nls_cp437", "nls_iso8859-1"])?;
    let slot = Slot::load()?;
    let protected_epoch = Path::new("/usr/lib/fvca/hypervisor-epoch").try_exists()?;
    hypervisor_trial::verify_standing_key(&cmdline)?;
    hypervisor_trial::guest_configuration::verify_key(&cmdline)?;
    let mut epochs = cmdline
        .split_ascii_whitespace()
        .filter(|arg| arg.split('=').next() == Some(HYPERVISOR_EPOCH_ARGUMENT));
    let epoch = epochs.next();
    if epochs.next().is_some() || epoch.is_some() != protected_epoch {
        return Err(invalid(
            "expected exactly one command-line epoch with the signed Hypervisor epoch policy",
        ));
    }
    let firmware_tpm = if let Some(epoch) = epoch {
        if slot.is_none() {
            return Err(invalid(
                "a protected Hypervisor epoch requires a verified GPT slot",
            ));
        }
        check_epoch(epoch)?
    } else {
        None
    };
    let verified_runtime = runtime::activate(Runtime::Vm, slot.as_ref().map(|slot| &slot.runtime))?;
    host_network::activate(&cmdline)?;
    host_workload::activate(&cmdline)?;
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
                firmware_tpm.as_ref(),
                recovery,
            );
        }
        Ok(false)
    };
    let firmware_pending = fvca_trial_authorization::firmware::activation_pending()?;
    if firmware_pending {
        hypervisor_trial::guest_configuration::require_committed(&cmdline)?;
        hypervisor_trial::stop_candidate_watchdog_for_firmware(&cmdline)?;
        println!("FVCA_HOST_FIRMWARE_RECOVERY_REQUIRED");
        if !enroll_firmware(true)? {
            kernel_policy::seal()?;
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
    let guest =
        guest_boot::activate_if_selected(startup, slot.as_ref().map(|slot| &slot.guest), &cmdline)?;
    if !firmware_pending {
        let standing_candidate = hypervisor_trial::start_candidate(
            &cmdline,
            slot.as_ref(),
            guest.as_deref(),
            &verified_runtime,
            recovering,
            epoch,
        )?;
        if !standing_candidate {
            hypervisor_trial::guest_configuration::require_committed(&cmdline)?;
        }
        match hypervisor_trial::arm_if_authorized(
            esp,
            guest.as_deref(),
            &verified_runtime,
            epoch,
            &cmdline,
        ) {
            Ok(hypervisor_trial::ArmOutcome::RebootIntoTrial) => {
                kernel_policy::seal()?;
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
    if !recovering && !firmware_pending {
        host_update::publish_management_enrollment(&cmdline)?;
    }
    if !recovering && !Path::new("/run/fvca/boot-trial-started").try_exists()? {
        if guest.is_some() {
            host_update::activate_guest_if_selected()?;
        }
        if !firmware_pending {
            enroll_firmware(false)?;
        }
    }

    kernel_policy::seal()?;
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
