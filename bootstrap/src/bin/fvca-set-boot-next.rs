#![forbid(unsafe_code)]

use std::alloc::System;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::process::ExitCode;

use fvca_initrd_bootstrap::{hypervisor_trial::boot_next_path, invalid};

#[global_allocator]
static ALLOCATOR: System = System;

fn arm() -> io::Result<()> {
    fvca_allocator_binding::require_allocator()?;
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [number] = args.as_slice() else {
        return Err(invalid("expected an EFI boot entry number"));
    };
    let number = number
        .to_str()
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| invalid("invalid EFI boot entry number"))?;

    let mut payload = [7, 0, 0, 0, 0, 0];
    payload[4..].copy_from_slice(&number.to_le_bytes());
    let mut variable = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(boot_next_path())?;
    if variable.write(&payload)? != payload.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "incomplete EFI variable write",
        ));
    }
    Ok(())
}

fn main() -> ExitCode {
    if let Err(error) = arm() {
        eprintln!("FVCA could not set EFI BootNext: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
