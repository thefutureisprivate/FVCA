#![forbid(unsafe_code)]

use std::alloc::System;
use std::fs;
use std::io;
use std::os::unix::fs::FileTypeExt;
use std::process::ExitCode;

use fvca_initrd_bootstrap::{backup_policy, guest_boot, invalid};
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
    let runtime_hash = runtime::activate(Runtime::Vm)?;
    runtime::install_development_probe("fvca-vm-runtime-probe.service", PROBE)?;
    storage::activate_if_selected()?;
    guest_boot::activate_if_selected()?;
    backup_policy::activate_if_selected()?;

    println!("FVCA_VM_RUNTIME_ACTIVE {runtime_hash}");
    Ok(())
}

fn main() -> ExitCode {
    if let Err(error) = activate() {
        eprintln!("FVCA VM runtime activation failed: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
