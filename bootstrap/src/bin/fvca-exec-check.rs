//! Exercise execution-policy denials in a disposable signed development image.

use std::alloc::System;
use std::ffi::{c_int, c_long, c_void};
use std::fs::{self, File};
use std::io::{self, ErrorKind};
use std::os::fd::{FromRawFd, OwnedFd};
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
const PERF_EVENT_OPEN: c_long = 298;
const CAP_SYS_RAWIO: u64 = 1 << 17;

// PERF_ATTR_SIZE_VER0 from linux/perf_event.h suffices for a software CPU clock event.
#[repr(C)]
struct PerfEvent {
    kind: u32,
    size: u32,
    config: u64,
    sample_period: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup_events: u32,
    breakpoint_type: u32,
    breakpoint_address: u64,
}

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
    fn syscall(number: c_long, ...) -> c_long;
}

fn anonymous_mapping(protection: c_int) -> io::Result<*mut c_void> {
    // The kernel chooses the address. Anonymous mappings take no file descriptor.
    let mapped = unsafe {
        mmap(
            ptr::null_mut(),
            LEN,
            protection,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
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
        Err(error) => Err(io::Error::other(format!(
            "{case}: unexpected error {error}"
        ))),
        Ok(_) => Err(io::Error::other(format!("{case}: unexpectedly allowed"))),
    }
}

fn open_perf_event() -> io::Result<OwnedFd> {
    let event = PerfEvent {
        kind: 1, // PERF_TYPE_SOFTWARE
        size: size_of::<PerfEvent>() as u32,
        config: 0, // PERF_COUNT_SW_CPU_CLOCK
        sample_period: 0,
        sample_type: 0,
        read_format: 0,
        flags: (1 << 0) | (1 << 5) | (1 << 6), // disabled, exclude kernel and hypervisor
        wakeup_events: 0,
        breakpoint_type: 0,
        breakpoint_address: 0,
    };
    // Open a disabled event for this thread. The kernel only reads the ABI structure.
    let fd = unsafe { syscall(PERF_EVENT_OPEN, &raw const event, 0, -1, -1, 0_u64) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // A successful perf_event_open returns a new descriptor owned by this process.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as c_int) })
}

fn check_kernel_interfaces() -> io::Result<()> {
    let status = fs::read_to_string("/proc/self/status")?;
    for field in ["CapBnd:\t", "CapEff:\t"] {
        let set = status
            .lines()
            .find_map(|line| line.strip_prefix(field))
            .and_then(|bits| u64::from_str_radix(bits, 16).ok())
            .ok_or_else(|| io::Error::other("missing process capability set"))?;
        if set & CAP_SYS_RAWIO != 0 {
            return Err(io::Error::other("service retains CAP_SYS_RAWIO"));
        }
    }
    require_denied("kernel-memory", File::open("/proc/kcore"))?;
    require_denied(
        "kernel-tracing",
        File::open("/sys/kernel/tracing/tracing_on"),
    )?;
    require_denied("performance-counters", open_perf_event())
}

fn check() -> io::Result<()> {
    fvca_allocator_binding::require_allocator()?;
    check_kernel_interfaces()?;
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
    fs::copy(source, copy)?;
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
