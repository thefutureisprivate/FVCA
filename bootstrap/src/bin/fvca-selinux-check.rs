#![forbid(unsafe_code)]

use std::alloc::System;
use std::fs;
use std::io::{self, Read, Write};
use std::process::ExitCode;

#[global_allocator]
static ALLOCATOR: System = System;

fn verify_pcr_domain() -> io::Result<()> {
    const AVD_FLAGS_PERMISSIVE: u32 = 1;
    let class = fs::read_to_string("/sys/fs/selinux/class/process/index")?;
    let request = format!(
        "system_u:system_r:systemd_pcrextend_t:s0 system_u:system_r:init_t:s0 {}",
        class.trim_end(),
    );
    // The selinuxfs access file returns the kernel's access decision and flags
    // on the same descriptor that received the request.
    let mut access = fs::OpenOptions::new().read(true).write(true).open("/sys/fs/selinux/access")?;
    access.write_all(request.as_bytes())?;
    let mut response = String::new();
    access.read_to_string(&mut response)?;
    let flags = response.split_ascii_whitespace().nth(5)
        .and_then(|field| u32::from_str_radix(field, 16).ok())
        .ok_or_else(|| io::Error::other("missing SELinux access decision flags"))?;
    if flags & AVD_FLAGS_PERMISSIVE != 0 {
        return Err(io::Error::other("the PCR measurement domain is permissive"));
    }
    Ok(())
}

fn verify_selinux() -> io::Result<()> {
    let enforcing = fs::read_to_string("/sys/fs/selinux/enforce")
        .map_err(|error| io::Error::other(format!("cannot read SELinux enforcing state: {error}")))?;
    if enforcing.trim_end() != "1" {
        return Err(io::Error::other("SELinux is not enforcing"));
    }
    let context = fs::read_to_string("/proc/1/attr/current")
        .map_err(|error| io::Error::other(format!("cannot read PID 1 security context: {error}")))?;
    if context.trim_end_matches(['\0', '\n']) != "system_u:system_r:init_t:s0" {
        return Err(io::Error::other(format!("unexpected PID 1 SELinux context: {context:?}")));
    }
    verify_pcr_domain().map_err(|error| io::Error::other(format!("PCR measurement confinement: {error}")))
}

fn main() -> ExitCode {
    if let Err(error) = fvca_allocator_binding::require_allocator().and_then(|()| verify_selinux()) {
        eprintln!("FVCA SELinux check failed: {error}");
        return ExitCode::FAILURE;
    }
    println!("FVCA_SELINUX_PCR_CONFINED");
    println!("FVCA_SELINUX_ENFORCING");
    ExitCode::SUCCESS
}
