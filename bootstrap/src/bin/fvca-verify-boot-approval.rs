#![forbid(unsafe_code)]

use std::alloc::System;
use std::fs::File;
use std::io::{self, Read};
use std::process::ExitCode;

use fvca_initrd_bootstrap::{
    hypervisor_trial::{APPROVAL_LIMIT, PROMOTION_KEY, TRIAL_KEY},
    invalid,
};

#[global_allocator]
static ALLOCATOR: System = System;

fn verify() -> io::Result<()> {
    fvca_allocator_binding::require_allocator()?;
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let path = match args.as_slice() {
        [mode] if mode == "promotion" => PROMOTION_KEY,
        [mode] if mode == "trial" => TRIAL_KEY,
        _ => return Err(invalid("expected a boot approval purpose")),
    };
    let mut key = Vec::new();
    File::open(path)?.take(33).read_to_end(&mut key)?;
    let key = key
        .as_slice()
        .try_into()
        .map_err(|_| invalid("invalid Ed25519 boot approval key length"))?;
    let mut envelope = Vec::new();
    io::stdin()
        .lock()
        .take((APPROVAL_LIMIT + 1) as u64)
        .read_to_end(&mut envelope)?;
    let (signature, message) = envelope
        .split_first_chunk::<64>()
        .filter(|(_, body)| !body.is_empty() && envelope.len() <= APPROVAL_LIMIT)
        .ok_or_else(|| invalid("invalid signed boot approval envelope size"))?;
    fvca_signature_boundary::verify_ed25519(key, signature, message)
}

fn main() -> ExitCode {
    if let Err(error) = verify() {
        eprintln!("FVCA could not verify boot approval: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
