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

fn field<'a>(status: &'a str, label: &str) -> Option<&'a str> {
    status.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key == label).then(|| value.trim())
    })
}

fn check_process(proc: &Path) -> io::Result<()> {
    let context = fs::read_to_string(proc.join("attr/current"))?;
    let context = context.trim_end_matches(['\0', '\n']);
    require(context.starts_with("system_u:system_r:svirt_t:s0:c"), "QEMU lacks an sVirt MCS label")?;

    let status = fs::read_to_string(proc.join("status"))?;
    let uid = field(&status, "Uid").and_then(|value| value.split_ascii_whitespace().nth(1));
    require(uid == Some("107"), "QEMU has an unexpected effective UID")?;
    require(field(&status, "NoNewPrivs") == Some("1"), "QEMU lacks no-new-privileges")?;
    require(field(&status, "Seccomp") == Some("2"), "QEMU lacks a seccomp filter")?;
    require(field(&status, "CapEff") == Some("0000000000000000"), "QEMU retains capabilities")?;
    let namespace = fs::read_link(proc.join("ns/mnt"))?;
    require(namespace != fs::read_link("/proc/1/ns/mnt")?, "QEMU lacks a private mount namespace")?;
    println!("FVCA_KVM_GUEST_CONFINED {context}");
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
    check_process(&Path::new("/proc").join(pid.to_string()))?;

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
