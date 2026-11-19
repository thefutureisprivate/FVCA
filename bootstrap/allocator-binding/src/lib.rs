//! Inspect the providers of this process's allocator relocations through glibc.

use std::ffi::{CStr, c_char, c_int, c_void};
use std::io;
use std::mem::MaybeUninit;

const LIBRARY: &str = "/usr/lib64/fvca/libhardened_malloc.so";

#[repr(C)]
struct DlInfo {
    filename: *const c_char,
    base: *mut c_void,
    symbol: *const c_char,
    symbol_address: *mut c_void,
}

unsafe extern "C" {
    fn dladdr(address: *const c_void, info: *mut DlInfo) -> c_int;
    fn malloc(size: usize) -> *mut c_void;
    fn calloc(count: usize, size: usize) -> *mut c_void;
    fn realloc(pointer: *mut c_void, size: usize) -> *mut c_void;
    fn free(pointer: *mut c_void);
    fn posix_memalign(pointer: *mut *mut c_void, alignment: usize, size: usize) -> c_int;
}

pub fn require_allocator() -> io::Result<()> {
    let preload = std::fs::read("/etc/ld.so.preload")?;
    if preload.strip_suffix(b"\n") != Some(LIBRARY.as_bytes()) {
        return Err(io::Error::other("unexpected allocator preload configuration"));
    }

    for (name, address) in [
        ("malloc", malloc as *const c_void),
        ("calloc", calloc as *const c_void),
        ("realloc", realloc as *const c_void),
        ("free", free as *const c_void),
        ("posix_memalign", posix_memalign as *const c_void),
    ] {
        let mut info = MaybeUninit::<DlInfo>::uninit();
        // glibc initializes Dl_info on success. These addresses come from live ELF relocations.
        if unsafe { dladdr(address, info.as_mut_ptr()) } == 0 {
            return Err(io::Error::other(format!("unknown provider for {name}")));
        }
        let filename = unsafe { info.assume_init() }.filename;
        // The loader owns this NUL-terminated path for the lifetime of the loaded object.
        if filename.is_null() || unsafe { CStr::from_ptr(filename) }.to_bytes() != LIBRARY.as_bytes()
        {
            return Err(io::Error::other(format!("{name} is not bound to {LIBRARY}")));
        }
    }
    Ok(())
}
