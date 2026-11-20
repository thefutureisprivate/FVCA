#![forbid(unsafe_code)]

use std::alloc::System;
use std::io;
use std::process::ExitCode;

use fvca_initrd_bootstrap::{hypervisor_trial, invalid};

#[global_allocator]
static ALLOCATOR: System = System;

fn promote() -> io::Result<()> {
    fvca_allocator_binding::require_allocator()?;
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [stable, candidate] = args.as_slice() else {
        return Err(invalid("expected stable and candidate boot entry numbers"));
    };
    let parse = |value: &std::ffi::OsStr| {
        value
            .to_str()
            .and_then(|text| text.parse::<u16>().ok())
            .ok_or_else(|| invalid("invalid boot entry number"))
    };
    hypervisor_trial::write_promoted_order(parse(stable)?, parse(candidate)?)
}

fn main() -> ExitCode {
    if let Err(error) = promote() {
        eprintln!("FVCA could not promote the EFI boot order: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
