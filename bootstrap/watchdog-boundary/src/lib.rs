//! The Linux x86-64 watchdog ioctl boundary.

use std::ffi::{c_int, c_ulong};
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;

// _IOWR('W', 6, int) and _IOR('W', 4, int) from linux/watchdog.h.
const WDIOC_SETTIMEOUT: c_ulong = 0xc004_5706;
const WDIOC_SETOPTIONS: c_ulong = 0x8004_5704;
const WDIOS_DISABLECARD: c_int = 1;

unsafe extern "C" {
    fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
}

fn operation(device: &File, request: c_ulong, mut value: c_int) -> io::Result<c_int> {
    // Both commands take a pointer to one initialized int. The borrowed file
    // keeps the descriptor open for the duration of the ioctl.
    if unsafe { ioctl(device.as_raw_fd(), request, &raw mut value) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(value)
}

pub fn set_timeout(device: &File, seconds: i32) -> io::Result<i32> {
    operation(device, WDIOC_SETTIMEOUT, seconds)
}

pub fn stop(device: &File) -> io::Result<()> {
    operation(device, WDIOC_SETOPTIONS, WDIOS_DISABLECARD).map(|_| ())
}
