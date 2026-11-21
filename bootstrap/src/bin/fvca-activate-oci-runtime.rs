#![forbid(unsafe_code)]

use std::alloc::System;
use std::fs;
use std::io;
use std::path::Path;
use std::process::ExitCode;

use fvca_initrd_bootstrap::runtime::{self, Runtime};
use fvca_initrd_bootstrap::{direct_boot, invalid, kernel_policy, workload_network};

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
    kernel_policy::require_signed_modules()?;
    let direct = Path::new(direct_boot::READY_IN_INITRD).is_file();
    if !direct {
        kernel_policy::load_modules(&[
            "loop",
            "virtio_console",
            "virtio_net",
            "nf_tables",
            "nft_ct",
            "nft_limit",
        ])?;
    }
    let runtime_hash = runtime::activate(Runtime::Oci, None)?.extension;
    let trust = workload_trust::enroll()?;
    workload_network::activate(&fs::read_to_string("/proc/cmdline")?, trust)?;
    kernel_policy::seal()?;
    let quadlets = "/run/fvca/oci-probe-quadlet";
    fs::create_dir_all(quadlets)?;
    fs::write(
        format!("{quadlets}/fvca-oci-runtime-probe.container"),
        QUADLET,
    )?;
    runtime::install_development_probe("fvca-oci-runtime-probe.service", PROBE)?;
    // Report the bootstrap proof again after the Guest console is established.
    if direct {
        println!("FVCA_OCI_RUNTIME_ACTIVE {runtime_hash} FVCA_DIRECT_BOOT_POLICY_ACTIVE");
    } else {
        println!("FVCA_OCI_RUNTIME_ACTIVE {runtime_hash}");
    }
    Ok(())
}

fn main() -> ExitCode {
    if let Err(error) = activate() {
        eprintln!("FVCA OCI runtime activation failed: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
