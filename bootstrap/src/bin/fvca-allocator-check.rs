#![forbid(unsafe_code)]

use std::alloc::System;
use std::hint::black_box;
use std::process::ExitCode;

#[global_allocator]
static ALLOCATOR: System = System;

fn main() -> ExitCode {
    if let Err(error) = fvca_allocator_binding::require_allocator() {
        eprintln!("FVCA allocator check failed: {error}");
        return ExitCode::FAILURE;
    }

    let mut data = Vec::new();
    if let Err(error) = data.try_reserve_exact(128) {
        eprintln!("FVCA allocator check could not allocate memory: {error}");
        return ExitCode::FAILURE;
    }
    data.resize(128, 42_u8);
    black_box(&data);
    drop(data);
    println!("FVCA_ALLOCATOR_CHECK_PASSED");
    ExitCode::SUCCESS
}
