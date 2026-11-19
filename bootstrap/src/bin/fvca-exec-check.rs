//! Exercise execution-policy denials in a disposable signed development image.

use std::alloc::System;
use std::ffi::{c_int, c_void};
use std::io::{self, ErrorKind};
use std::process::{Command, ExitCode};
use std::ptr;

#[global_allocator]
static ALLOCATOR: System = System;

// Linux x86-64 mmap ABI. This fixture is compiled only for that target.
const PROT_READ: c_int = 1;
const PROT_WRITE: c_int = 2;
const PROT_EXEC: c_int = 4;
const MAP_PRIVATE: c_int = 0x02;
const MAP_ANONYMOUS: c_int = 0x20;
const LEN: usize = 4096;
const MAP_FAILED: *mut c_void = ptr::without_provenance_mut(usize::MAX);

unsafe extern "C" {
    fn mmap(
        addr: *mut c_void,
        length: usize,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        offset: i64,
    ) -> *mut c_void;
    fn mprotect(addr: *mut c_void, length: usize, prot: c_int) -> c_int;
    fn munmap(addr: *mut c_void, length: usize) -> c_int;
}

fn anonymous_mapping(protection: c_int) -> io::Result<*mut c_void> {
    // The kernel chooses the address. Anonymous mappings take no file descriptor.
    let mapped = unsafe {
        mmap(ptr::null_mut(), LEN, protection, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
    };
    if mapped == MAP_FAILED {
        Err(io::Error::last_os_error())
    } else {
        Ok(mapped)
    }
}

fn unmap(mapped: *mut c_void) -> io::Result<()> {
    // Both callers pass a live, successful mapping of LEN bytes.
    if unsafe { munmap(mapped, LEN) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn require_denied<T>(case: &str, result: io::Result<T>) -> io::Result<()> {
    match result {
        Err(error) if error.kind() == ErrorKind::PermissionDenied => {
            println!("FVCA_EXEC_CHECK {case}: denied");
            Ok(())
        }
        Err(error) => Err(io::Error::other(format!("{case}: unexpected error {error}"))),
        Ok(_) => Err(io::Error::other(format!("{case}: unexpectedly allowed"))),
    }
}

fn check() -> io::Result<()> {
    fvca_allocator_binding::require_allocator()?;
    for (case, flags) in [
        ("anonymous-rx", PROT_READ | PROT_EXEC),
        ("anonymous-rwx", PROT_READ | PROT_WRITE | PROT_EXEC),
    ] {
        let result = anonymous_mapping(flags);
        if let Ok(address) = &result {
            unmap(*address)?;
        }
        require_denied(case, result)?;
    }

    let address = anonymous_mapping(PROT_READ | PROT_WRITE)?;
    // Write inside the live mapping. The test never calls into the mapping.
    unsafe { address.cast::<u8>().write(0) };
    let result = if unsafe { mprotect(address, LEN, PROT_READ | PROT_EXEC) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    };
    unmap(address)?;
    require_denied("writable-to-executable", result)?;

    let source = "/usr/bin/true";
    let copy = "/run/fvca-exec-check/true";
    if !Command::new(source).status()?.success() {
        return Err(io::Error::other("program on the verified root failed"));
    }
    std::fs::copy(source, copy)?;
    require_denied("tmpfs-exec", Command::new(copy).status())?;
    println!("FVCA_EXEC_CHECK_PASSED");
    Ok(())
}

fn main() -> ExitCode {
    match check() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("FVCA_EXEC_CHECK_FAILED {error}");
            ExitCode::FAILURE
        }
    }
}
