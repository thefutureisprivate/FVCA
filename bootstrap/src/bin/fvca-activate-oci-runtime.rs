#![forbid(unsafe_code)]

use std::alloc::System;
use std::fs;
use std::io;
use std::process::ExitCode;

use fvca_initrd_bootstrap::invalid;
use fvca_initrd_bootstrap::runtime::{self, Runtime};

#[path = "fvca-activate-oci-runtime/workload_trust.rs"]
mod workload_trust;

#[global_allocator]
static ALLOCATOR: System = System;

const PROBE: &str = include_str!("../../../tests/fvca-oci-runtime-probe.service");
const QUADLET: &str = include_str!("../../../tests/fvca-oci-runtime-probe.container");

fn activate() -> io::Result<()> {
    fvca_allocator_binding::require_allocator()?;
    if fs::symlink_metadata("/dev/kvm").is_ok() || fs::metadata("/sys/module/kvm").is_ok() {
        return Err(invalid("KVM must be unavailable inside the Service Guest"));
    }
    if fs::read_to_string("/sysroot/usr/lib/fvca/role")? != "service-guest\n" {
        return Err(invalid("expected a Service Guest core"));
    }
    let runtime_hash = runtime::activate(Runtime::Oci)?;
    workload_trust::enroll()?;
    let quadlets = "/run/fvca/oci-probe-quadlet";
    fs::create_dir_all(quadlets)?;
    fs::write(format!("{quadlets}/fvca-oci-runtime-probe.container"), QUADLET)?;
    runtime::install_development_probe("fvca-oci-runtime-probe.service", PROBE)?;
    println!("FVCA_OCI_RUNTIME_ACTIVE {runtime_hash}");
    Ok(())
}

fn main() -> ExitCode {
    if let Err(error) = activate() {
        eprintln!("FVCA OCI runtime activation failed: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
