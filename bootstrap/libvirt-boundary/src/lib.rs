//! Own the libvirt connection and transient domain handles used by the Hypervisor.

use std::ffi::{CStr, c_char, c_int, c_uint, c_void};
use std::io;
use std::marker::PhantomData;
use std::ptr::{NonNull, null_mut};

const LOCAL_QEMU: &CStr = c"qemu+unix:///system?socket=/run/libvirt/virtqemud-sock";
const START_AUTODESTROY: c_uint = 2;
const START_PAUSED: c_uint = 1;
const START_VALIDATE: c_uint = 16;
const CONSOLE_SAFE: c_uint = 2;
const STREAM_NONBLOCK: c_uint = 1;
const SHUTDOWN_ACPI: c_uint = 1;
const NO_DOMAIN: c_int = 42;
pub const RUNNING: c_int = 1;
pub const PAUSED: c_int = 3;

#[link(name = "virt")]
unsafe extern "C" {
    fn virConnectOpen(uri: *const c_char) -> *mut c_void;
    fn virConnectClose(connection: *mut c_void) -> c_int;
    fn virDomainCreateXML(connection: *mut c_void, xml: *const c_char, flags: c_uint) -> *mut c_void;
    fn virDomainGetState(domain: *mut c_void, state: *mut c_int, reason: *mut c_int, flags: c_uint) -> c_int;
    fn virDomainLookupByUUIDString(connection: *mut c_void, uuid: *const c_char) -> *mut c_void;
    fn virDomainIsActive(domain: *mut c_void) -> c_int;
    fn virDomainShutdownFlags(domain: *mut c_void, flags: c_uint) -> c_int;
    fn virGetLastErrorCode() -> c_int;
    fn virDomainSuspend(domain: *mut c_void) -> c_int;
    fn virDomainResume(domain: *mut c_void) -> c_int;
    fn virDomainDestroy(domain: *mut c_void) -> c_int;
    fn virDomainFree(domain: *mut c_void) -> c_int;
    fn virDomainOpenConsole(domain: *mut c_void, device: *const c_char, stream: *mut c_void, flags: c_uint) -> c_int;
    fn virStreamNew(connection: *mut c_void, flags: c_uint) -> *mut c_void;
    fn virStreamRecv(stream: *mut c_void, data: *mut c_char, length: usize) -> c_int;
    fn virStreamAbort(stream: *mut c_void) -> c_int;
    fn virStreamFree(stream: *mut c_void) -> c_int;
    fn virEventRegisterDefaultImpl() -> c_int;
    fn virEventRunDefaultImpl() -> c_int;
    fn virEventAddTimeout(interval: c_int, callback: extern "C" fn(c_int, *mut c_void),
                          opaque: *mut c_void, free: Option<extern "C" fn(*mut c_void)>) -> c_int;
    fn virEventRemoveTimeout(timer: c_int) -> c_int;
}

pub struct Connection(NonNull<c_void>);
pub struct EventLoop(c_int);

pub struct Domain<'connection> {
    handle: NonNull<c_void>,
    _connection: &'connection Connection,
}

pub struct Console<'domain> {
    stream: NonNull<c_void>,
    _domain: PhantomData<&'domain ()>,
}

fn status(code: c_int, operation: &'static str) -> io::Result<()> {
    if code < 0 {
        return Err(io::Error::other(operation));
    }
    Ok(())
}

impl EventLoop {
    pub fn register() -> io::Result<Self> {
        // Install the reactor before opening the libvirt connection so the
        // client can receive asynchronous console stream packets.
        status(unsafe { virEventRegisterDefaultImpl() }, "could not register the libvirt event loop")?;
        extern "C" fn wake(_: c_int, _: *mut c_void) {}
        // A stateless periodic wakeup lets the launcher enforce its deadline
        // even when no guest output or connection events arrive.
        let timer = unsafe { virEventAddTimeout(20, wake, null_mut(), None) };
        status(timer, "could not set the libvirt wakeup timer")?;
        Ok(Self(timer))
    }

    pub fn poll(&self) -> io::Result<()> {
        // libvirt dispatches events once and our timer bounds the idle poll.
        status(unsafe { virEventRunDefaultImpl() }, "could not dispatch libvirt events")
    }
}

impl Drop for EventLoop {
    fn drop(&mut self) {
        // The timer ID belongs to this instance.
        unsafe { virEventRemoveTimeout(self.0) };
    }
}

impl Connection {
    pub fn connect() -> io::Result<Self> {
        // libvirt reads this NUL-terminated static C string and returns an owned reference.
        NonNull::new(unsafe { virConnectOpen(LOCAL_QEMU.as_ptr()) })
            .map(Self)
            .ok_or_else(|| io::Error::other("could not connect to the local QEMU driver"))
    }

    pub fn start(&self, xml: &CStr) -> io::Result<Domain<'_>> {
        self.create(xml, START_AUTODESTROY)
    }

    pub fn start_registered(&self, xml: &CStr) -> io::Result<Domain<'_>> {
        // The actual Guest must remain eligible for provider snapshots.
        self.create(xml, START_PAUSED | START_VALIDATE)
    }

    fn create(&self, xml: &CStr, flags: c_uint) -> io::Result<Domain<'_>> {
        // The live connection and CStr outlive the call.
        let handle = unsafe { virDomainCreateXML(self.0.as_ptr(), xml.as_ptr(), flags) };
        let handle = NonNull::new(handle).ok_or_else(|| io::Error::other("could not start the approved KVM domain"))?;
        Ok(Domain { handle, _connection: self })
    }

    pub fn lookup(&self, uuid: &CStr) -> io::Result<Option<Domain<'_>>> {
        // The connection and UUID outlive the call. The error is thread-local.
        let handle = unsafe { virDomainLookupByUUIDString(self.0.as_ptr(), uuid.as_ptr()) };
        if let Some(handle) = NonNull::new(handle) {
            return Ok(Some(Domain { handle, _connection: self }));
        }
        if unsafe { virGetLastErrorCode() } == NO_DOMAIN {
            return Ok(None);
        }
        Err(io::Error::other("could not look up the registered VM"))
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        // This is our last reference and the borrow prevents live Domain handles here.
        unsafe { virConnectClose(self.0.as_ptr()) };
    }
}

impl Domain<'_> {
    pub fn is_active(&self) -> io::Result<bool> {
        // The handle refers to one domain owned by the live connection.
        let active = unsafe { virDomainIsActive(self.handle.as_ptr()) };
        if active < 0 && unsafe { virGetLastErrorCode() } == NO_DOMAIN {
            return Ok(false);
        }
        status(active, "could not check whether the registered VM is active")?;
        Ok(active != 0)
    }

    pub fn console(&self) -> io::Result<Console<'_>> {
        // The borrowed domain keeps the underlying connection alive for the stream.
        let stream = unsafe { virStreamNew(self._connection.0.as_ptr(), STREAM_NONBLOCK) };
        let stream = NonNull::new(stream).ok_or_else(|| io::Error::other("could not allocate a Guest console stream"))?;
        let console = Console { stream, _domain: PhantomData };
        // There is just one configured console. SAFE rejects a competing reader.
        let result = unsafe { virDomainOpenConsole(self.handle.as_ptr(), std::ptr::null(), stream.as_ptr(), CONSOLE_SAFE) };
        status(result, "could not open the Guest console")?;
        Ok(console)
    }

    pub fn shutdown(&self) -> io::Result<()> {
        // Only the configured power button is available in this Guest definition.
        status(unsafe { virDomainShutdownFlags(self.handle.as_ptr(), SHUTDOWN_ACPI) }, "could not shut down the Guest")
    }

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

impl Console<'_> {
    pub fn receive(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        // libvirt can write at most buffer.len() bytes to this owned slice.
        match unsafe { virStreamRecv(self.stream.as_ptr(), buffer.as_mut_ptr().cast(), buffer.len()) } {
            -2 => Ok(0),
            0 => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the Guest console closed")),
            count if count > 0 => Ok(count as usize),
            _ => Err(io::Error::other("could not read the Guest console")),
        }
    }
}

impl Drop for Console<'_> {
    fn drop(&mut self) {
        // End console forwarding and release our stream reference.
        unsafe {
            virStreamAbort(self.stream.as_ptr());
            virStreamFree(self.stream.as_ptr());
        }
    }
}
