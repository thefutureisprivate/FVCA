#![forbid(unsafe_code)]

use std::alloc::System;
use std::ffi::CString;
use std::fs;
use std::io;
use std::path::Path;
use std::process::ExitCode;

use fvca_libvirt_boundary::{Connection, PAUSED, RUNNING};

#[global_allocator]
static ALLOCATOR: System = System;

const FIXTURE: &str = include_str!("../../../tests/fvca-kvm-fixture.xml");
const PID_FILE: &str = "/run/libvirt/qemu/fvca-qualification.pid";

fn require(condition: bool, message: &str) -> io::Result<()> {
    if !condition {
        return Err(io::Error::other(message));
    }
    Ok(())
}

fn qualify() -> io::Result<()> {
    fvca_allocator_binding::require_allocator()?;
    let xml = CString::new(FIXTURE).map_err(io::Error::other)?;
    let connection = Connection::connect()?;
    let domain = connection.start(&xml)?;
    require(domain.state()? == RUNNING, "the KVM fixture did not start")?;
    let pid: u32 = fs::read_to_string(PID_FILE)?.trim().parse().map_err(io::Error::other)?;
    require(pid > 1, "invalid libvirt guest PID")?;
    fvca_initrd_bootstrap::vm_confinement::check_process(&Path::new("/proc").join(pid.to_string()))?;

    domain.suspend()?;
    require(domain.state()? == PAUSED, "the KVM fixture did not suspend")?;
    domain.resume()?;
    require(domain.state()? == RUNNING, "the KVM fixture did not resume")?;
    domain.destroy()?;
    require(!Path::new(PID_FILE).try_exists()?, "the KVM fixture still has a PID file")?;
    println!("FVCA_LIBVIRT_LIFECYCLE_OK");
    Ok(())
}

fn main() -> ExitCode {
    if let Err(error) = qualify() {
        eprintln!("FVCA libvirt qualification failed: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
