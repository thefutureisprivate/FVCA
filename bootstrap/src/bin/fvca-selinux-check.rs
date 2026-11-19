#![forbid(unsafe_code)]

use std::alloc::System;
use std::fs;
use std::io;
use std::process::ExitCode;

#[global_allocator]
static ALLOCATOR: System = System;

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
    Ok(())
}

fn main() -> ExitCode {
    if let Err(error) = fvca_allocator_binding::require_allocator().and_then(|()| verify_selinux()) {
        eprintln!("FVCA SELinux check failed: {error}");
        return ExitCode::FAILURE;
    }
    println!("FVCA_SELINUX_ENFORCING");
    ExitCode::SUCCESS
}
