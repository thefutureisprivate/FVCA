//! Own the libvirt connection and transient domain handles used by the Hypervisor.

use std::ffi::{CStr, c_char, c_int, c_uint, c_void};
use std::io;
use std::marker::PhantomData;
use std::ptr::{NonNull, null_mut};
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

mod block_nodes;

const LOCAL_QEMU: &CStr = c"qemu+unix:///system?socket=/run/libvirt/virtqemud-sock";
const START_AUTODESTROY: c_uint = 2;
const START_PAUSED: c_uint = 1;
const START_VALIDATE: c_uint = 16;
const CONSOLE_SAFE: c_uint = 2;
const STREAM_NONBLOCK: c_uint = 1;
const SHUTDOWN_AGENT: c_uint = 2;
const NO_DOMAIN: c_int = 42;
const EVENT_LIFECYCLE: c_int = 0;
const EVENT_STOPPED: c_int = 5;
const STOPPED_SHUTDOWN: c_int = 0;
const STOP_PENDING: c_int = -1;
const AGENT_TIMEOUT_SECONDS: c_int = 5;
const PAUSED_SNAPSHOT: c_int = 9;
const SNAPSHOT_NO_METADATA: c_uint = 4;
const SNAPSHOT_DISK_ONLY: c_uint = 16;
const SNAPSHOT_VALIDATE: c_uint = 512;
const GUEST_DATA: &CStr = c"/run/fvca/guest-data";
const MANUAL_SNAPSHOT: &CStr = c"<domainsnapshot>
  <name>fvca-provider-capture</name>
  <memory snapshot='no'/>
  <disks>
    <disk name='vda' snapshot='no'/>
    <disk name='vdb' snapshot='no'/>
    <disk name='vdc' snapshot='manual'/>
  </disks>
</domainsnapshot>";
pub const RUNNING: c_int = 1;
pub const PAUSED: c_int = 3;

type LifecycleCallback = extern "C" fn(*mut c_void, *mut c_void, c_int, c_int, *mut c_void) -> c_int;

#[link(name = "virt")]
unsafe extern "C" {
    fn virConnectOpen(uri: *const c_char) -> *mut c_void;
    fn virConnectClose(connection: *mut c_void) -> c_int;
    fn virDomainCreateXML(connection: *mut c_void, xml: *const c_char, flags: c_uint) -> *mut c_void;
    fn virDomainGetState(domain: *mut c_void, state: *mut c_int, reason: *mut c_int, flags: c_uint) -> c_int;
    fn virDomainLookupByUUIDString(connection: *mut c_void, uuid: *const c_char) -> *mut c_void;
    fn virDomainIsActive(domain: *mut c_void) -> c_int;
    fn virDomainShutdownFlags(domain: *mut c_void, flags: c_uint) -> c_int;
    fn virDomainAgentSetResponseTimeout(domain: *mut c_void, timeout: c_int, flags: c_uint) -> c_int;
    fn virDomainFSFreeze(domain: *mut c_void, paths: *const *const c_char, count: c_uint, flags: c_uint) -> c_int;
    fn virDomainFSThaw(domain: *mut c_void, paths: *const *const c_char, count: c_uint, flags: c_uint) -> c_int;
    fn virDomainSnapshotCreateXML(domain: *mut c_void, xml: *const c_char, flags: c_uint) -> *mut c_void;
    fn virDomainSnapshotFree(snapshot: *mut c_void) -> c_int;
    fn virConnectDomainEventRegisterAny(
        connection: *mut c_void, domain: *mut c_void, event: c_int, callback: LifecycleCallback,
        opaque: *mut c_void, free: extern "C" fn(*mut c_void),
    ) -> c_int;
    fn virConnectDomainEventDeregisterAny(connection: *mut c_void, callback: c_int) -> c_int;
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

#[link(name = "virt-qemu")]
unsafe extern "C" {
    fn virDomainQemuAgentCommand(domain: *mut c_void, command: *const c_char, timeout: c_int, flags: c_uint) -> *mut c_char;
    fn virDomainQemuMonitorCommand(domain: *mut c_void, command: *const c_char, result: *mut *mut c_char, flags: c_uint) -> c_int;
}

unsafe extern "C" {
    fn free(pointer: *mut c_void);
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

struct StopEvent<'connection> {
    connection: &'connection Connection,
    callback: c_int,
    reason: Arc<AtomicI32>,
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

impl StopEvent<'_> {
    fn watch<'connection>(domain: &Domain<'connection>) -> io::Result<StopEvent<'connection>> {
        extern "C" fn record(_: *mut c_void, _: *mut c_void, event: c_int, detail: c_int, data: *mut c_void) -> c_int {
            if event == EVENT_STOPPED {
                // libvirt retains an Arc reference while callbacks can run.
                let reason = unsafe { &*data.cast::<AtomicI32>() };
                reason.store(detail, Ordering::Relaxed);
            }
            0
        }
        extern "C" fn discard(data: *mut c_void) {
            // The callback owns the reference transferred by Arc::into_raw.
            drop(unsafe { Arc::from_raw(data.cast::<AtomicI32>()) });
        }
        let reason = Arc::new(AtomicI32::new(STOP_PENDING));
        let data = Arc::into_raw(Arc::clone(&reason)).cast_mut().cast();
        // The C API accepts the event-specific callback signature for this event ID.
        let callback = unsafe {
            virConnectDomainEventRegisterAny(
                domain._connection.0.as_ptr(), domain.handle.as_ptr(), EVENT_LIFECYCLE, record, data, discard,
            )
        };
        if callback < 0 {
            // On registration failure the client retains ownership of the opaque argument.
            discard(data);
            return Err(io::Error::other("could not watch the registered VM lifecycle"));
        }
        Ok(StopEvent { connection: domain._connection, callback, reason })
    }
}

impl Drop for StopEvent<'_> {
    fn drop(&mut self) {
        // If deregistration fails, the registration retains its reference until connection cleanup.
        unsafe { virConnectDomainEventDeregisterAny(self.connection.0.as_ptr(), self.callback) };
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

    pub fn require_guest_agent(&self) -> io::Result<()> {
        self.agent_reply(c"{\"execute\":\"guest-ping\"}", |reply| {
            if reply != c"{\"return\":{}}" {
                return Err(io::Error::other("the Service Guest agent returned an unexpected ping response"));
            }
            Ok(())
        })
    }

    fn agent_reply<T>(&self, command: &CStr, read: impl FnOnce(&CStr) -> io::Result<T>) -> io::Result<T> {
        // Callers of the public boundary can only select fixed operations.
        let reply = unsafe {
            virDomainQemuAgentCommand(self.handle.as_ptr(), command.as_ptr(), AGENT_TIMEOUT_SECONDS, 0)
        };
        if reply.is_null() {
            return Err(io::Error::other("the Service Guest agent did not answer"));
        }
        // Libvirt serializes the owned response as compact JSON.
        let result = read(unsafe { CStr::from_ptr(reply) });
        unsafe { free(reply.cast()) };
        result
    }

    pub fn guest_frozen(&self) -> io::Result<bool> {
        self.agent_reply(c"{\"execute\":\"guest-fsfreeze-status\"}", |reply| match reply {
            value if value == c"{\"return\":\"frozen\"}" => Ok(true),
            value if value == c"{\"return\":\"thawed\"}" => Ok(false),
            _ => Err(io::Error::other("the Service Guest agent returned an unexpected freeze state")),
        })
    }

    /// Arm independent thaw recovery before calling. A timeout can leave the filesystem frozen.
    pub fn freeze_guest_data(&self) -> io::Result<()> {
        if self.guest_frozen()? {
            return Err(io::Error::other("the Guest data filesystem is already frozen"));
        }
        self.set_agent_timeout()?;
        let path = GUEST_DATA.as_ptr();
        // The call borrows a one-element array of mountpoint pointers.
        let count = unsafe { virDomainFSFreeze(self.handle.as_ptr(), &path, 1, 0) };
        if count != 1 {
            return Err(io::Error::other(format!("expected one Guest filesystem freeze, got {count}")));
        }
        if !self.guest_frozen()? {
            return Err(io::Error::other("the Guest data filesystem is still thawed"));
        }
        Ok(())
    }

    pub fn thaw_guest_data(&self) -> io::Result<()> {
        self.set_agent_timeout()?;
        // QGA thaws its frozen filesystems as a set. Guest policy confines the set.
        let count = unsafe { virDomainFSThaw(self.handle.as_ptr(), std::ptr::null(), 0, 0) };
        if count != 1 {
            return Err(io::Error::other(format!("expected one Guest filesystem thaw, got {count}")));
        }
        if self.guest_frozen()? {
            return Err(io::Error::other("the Guest data filesystem is still frozen"));
        }
        Ok(())
    }

    fn set_agent_timeout(&self) -> io::Result<()> {
        // This timeout applies to subsequent native libvirt Guest agent calls.
        status(unsafe { virDomainAgentSetResponseTimeout(self.handle.as_ptr(), AGENT_TIMEOUT_SECONDS, 0) },
               "could not set the Guest agent response timeout")
    }

    pub fn require_guest_disk_active(&self, active: bool) -> io::Result<()> {
        let mut reply = null_mut();
        let query = c"{\"execute\":\"query-named-block-nodes\",\"arguments\":{\"flat\":true}}";
        // The trusted local libvirt boundary exposes this fixed read-only query.
        // Libvirt records custom-monitor taint even for read-only commands.
        let result = unsafe { virDomainQemuMonitorCommand(self.handle.as_ptr(), query.as_ptr(), &mut reply, 0) };
        let Some(reply) = NonNull::new(reply) else {
            return Err(io::Error::other("QEMU did not return its block nodes"));
        };
        // libvirt transfers the reply to the caller. The parsed result borrows no reply data.
        let verified = status(result, "could not query the Guest block nodes")
            .and_then(|()| block_nodes::verify(unsafe { CStr::from_ptr(reply.as_ptr()) }, active));
        unsafe { free(reply.as_ptr().cast()) };
        verified
    }

    /// Arm independent resume recovery before calling. A failed check can leave the VM paused.
    pub fn pause_for_guest_disk_capture(&self) -> io::Result<()> {
        if self.state()? != RUNNING {
            return Err(io::Error::other("manual disk capture requires a running Service Guest"));
        }
        self.require_guest_disk_active(true)?;
        let flags = SNAPSHOT_DISK_ONLY | SNAPSHOT_NO_METADATA | SNAPSHOT_VALIDATE;
        // The only writable disk in the verified direct-boot fixture uses manual mode.
        let snapshot = unsafe { virDomainSnapshotCreateXML(self.handle.as_ptr(), MANUAL_SNAPSHOT.as_ptr(), flags) };
        let snapshot = NonNull::new(snapshot).ok_or_else(|| io::Error::other("libvirt manual disk snapshot failed"))?;
        status(unsafe { virDomainSnapshotFree(snapshot.as_ptr()) }, "could not release the manual snapshot handle")?;
        if !self.paused_for_snapshot()? {
            return Err(io::Error::other("libvirt did not pause the Service Guest for the manual snapshot"));
        }
        self.require_guest_disk_active(false)
    }

    pub fn paused_for_snapshot(&self) -> io::Result<bool> {
        let (state, reason) = self.state_with_reason()?;
        Ok(state == PAUSED && reason == PAUSED_SNAPSHOT)
    }

    pub fn shutdown(&self, events: &EventLoop, timeout: Duration) -> io::Result<()> {
        let stop = StopEvent::watch(self)?;
        let deadline = Instant::now() + timeout;
        self.set_agent_timeout()?;
        // Poweroff can close the Guest's bus before the agent's child receives
        // its reply. Observe the lifecycle even if delivery was uncertain.
        let request = status(
            unsafe { virDomainShutdownFlags(self.handle.as_ptr(), SHUTDOWN_AGENT) },
            "the Guest agent did not confirm delivery of the shutdown request",
        );
        while Instant::now() < deadline {
            match stop.reason.load(Ordering::Relaxed) {
                STOP_PENDING => {}
                STOPPED_SHUTDOWN if !self.is_active()? => return Ok(()),
                STOPPED_SHUTDOWN => {}
                reason => return Err(io::Error::other(format!("the Service Guest stopped with libvirt reason {reason}"))),
            }
            events.poll()?;
        }
        let message = "libvirt did not confirm an orderly Guest shutdown";
        Err(io::Error::new(io::ErrorKind::TimedOut, match request {
            Ok(()) => message.to_owned(),
            Err(error) => format!("{message}: {error}"),
        }))
    }

    pub fn state(&self) -> io::Result<c_int> {
        let (state, _) = self.state_with_reason()?;
        Ok(state)
    }

    fn state_with_reason(&self) -> io::Result<(c_int, c_int)> {
        let mut state = 0;
        let mut reason = 0;
        // libvirt writes the state and its reason into these two integers.
        let result = unsafe { virDomainGetState(self.handle.as_ptr(), &mut state, &mut reason, 0) };
        status(result, "could not read the VM state")?;
        Ok((state, reason))
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
