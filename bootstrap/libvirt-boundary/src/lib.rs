//! Own the libvirt connection and transient domain handles used by the Hypervisor.

use std::ffi::{CStr, c_char, c_int, c_uint, c_void};
use std::io;
use std::ptr::{NonNull, null_mut};

const LOCAL_QEMU: &CStr = c"qemu+unix:///system?socket=/run/libvirt/virtqemud-sock";
const START_AUTODESTROY: c_uint = 2;
pub const RUNNING: c_int = 1;
pub const PAUSED: c_int = 3;

#[link(name = "virt")]
unsafe extern "C" {
    fn virConnectOpen(uri: *const c_char) -> *mut c_void;
    fn virConnectClose(connection: *mut c_void) -> c_int;
    fn virDomainCreateXML(connection: *mut c_void, xml: *const c_char, flags: c_uint) -> *mut c_void;
    fn virDomainGetState(domain: *mut c_void, state: *mut c_int, reason: *mut c_int, flags: c_uint) -> c_int;
    fn virDomainSuspend(domain: *mut c_void) -> c_int;
    fn virDomainResume(domain: *mut c_void) -> c_int;
    fn virDomainDestroy(domain: *mut c_void) -> c_int;
    fn virDomainFree(domain: *mut c_void) -> c_int;
}

pub struct Connection(NonNull<c_void>);

pub struct Domain<'connection> {
    handle: NonNull<c_void>,
    _connection: &'connection Connection,
}

fn status(code: c_int, operation: &'static str) -> io::Result<()> {
    if code < 0 {
        return Err(io::Error::other(operation));
    }
    Ok(())
}

impl Connection {
    pub fn connect() -> io::Result<Self> {
        // libvirt reads this NUL-terminated static C string and returns an owned reference.
        NonNull::new(unsafe { virConnectOpen(LOCAL_QEMU.as_ptr()) })
            .map(Self)
            .ok_or_else(|| io::Error::other("could not connect to the local QEMU driver"))
    }

    pub fn start(&self, xml: &CStr) -> io::Result<Domain<'_>> {
        // The live connection and CStr outlive the call. AUTODESTROY ties the VM to this connection.
        let handle = unsafe { virDomainCreateXML(self.0.as_ptr(), xml.as_ptr(), START_AUTODESTROY) };
        let handle = NonNull::new(handle).ok_or_else(|| io::Error::other("could not start the approved KVM fixture"))?;
        Ok(Domain { handle, _connection: self })
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        // This is our last reference and the borrow prevents live Domain handles here.
        unsafe { virConnectClose(self.0.as_ptr()) };
    }
}

impl Domain<'_> {
    pub fn state(&self) -> io::Result<c_int> {
        let mut state = 0;
        // libvirt writes one C int and accepts a null reason pointer.
        let result = unsafe { virDomainGetState(self.handle.as_ptr(), &mut state, null_mut(), 0) };
        status(result, "could not read the VM state")?;
        Ok(state)
    }

    pub fn suspend(&self) -> io::Result<()> {
        // This object owns one live handle until Drop.
        status(unsafe { virDomainSuspend(self.handle.as_ptr()) }, "could not suspend the VM")
    }

    pub fn resume(&self) -> io::Result<()> {
        // This object owns one live handle until Drop.
        status(unsafe { virDomainResume(self.handle.as_ptr()) }, "could not resume the VM")
    }

    pub fn destroy(self) -> io::Result<()> {
        // Stopping the VM leaves its libvirt reference valid for Drop.
        status(unsafe { virDomainDestroy(self.handle.as_ptr()) }, "could not stop the VM")
    }
}

impl Drop for Domain<'_> {
    fn drop(&mut self) {
        // Free only this owned reference. The connection cleans up a running AUTODESTROY guest.
        unsafe { virDomainFree(self.handle.as_ptr()) };
    }
}
