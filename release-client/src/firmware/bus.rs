//! Minimal sd-bus client for Host firmware discovery and catalog admission.

use std::ffi::{CStr, c_char, c_int, c_void};
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::ptr::{self, NonNull};

use crate::{Result, invalid};

const CALL_TIMEOUT: u64 = 10_000_000;
const CATALOG_TIMEOUT: u64 = 120_000_000;
const CABINET_TIMEOUT: u64 = 120_000_000;
const STR_LIMIT: usize = 4096;
const ITEM_LIMIT: usize = 128;

#[repr(C)]
struct SdBus {
    _private: [u8; 0],
}

#[repr(C)]
struct SdBusMessage {
    _private: [u8; 0],
}

// sd-bus is supplied by the systemd base. Use the installed ELF ABI directly.
#[link(name = "libsystemd.so.0", kind = "dylib", modifiers = "+verbatim")]
unsafe extern "C" {
    fn sd_bus_new(output: *mut *mut SdBus) -> c_int;
    fn sd_bus_unref(bus: *mut SdBus) -> *mut SdBus;
    fn sd_bus_set_address(bus: *mut SdBus, address: *const c_char) -> c_int;
    fn sd_bus_set_bus_client(bus: *mut SdBus, enabled: c_int) -> c_int;
    fn sd_bus_negotiate_fds(bus: *mut SdBus, enabled: c_int) -> c_int;
    fn sd_bus_start(bus: *mut SdBus) -> c_int;
    fn sd_bus_call(
        bus: *mut SdBus,
        message: *mut SdBusMessage,
        timeout: u64,
        error: *mut c_void,
        output: *mut *mut SdBusMessage,
    ) -> c_int;
    fn sd_bus_message_new_method_call(
        bus: *mut SdBus,
        output: *mut *mut SdBusMessage,
        destination: *const c_char,
        path: *const c_char,
        interface: *const c_char,
        member: *const c_char,
    ) -> c_int;
    fn sd_bus_message_set_auto_start(message: *mut SdBusMessage, enabled: c_int) -> c_int;
    fn sd_bus_message_unref(message: *mut SdBusMessage) -> *mut SdBusMessage;
    fn sd_bus_message_read_basic(
        message: *mut SdBusMessage,
        kind: c_char,
        output: *mut c_void,
    ) -> c_int;
    fn sd_bus_message_append_basic(
        message: *mut SdBusMessage,
        kind: c_char,
        value: *const c_void,
    ) -> c_int;
    fn sd_bus_message_enter_container(
        message: *mut SdBusMessage,
        kind: c_char,
        contents: *const c_char,
    ) -> c_int;
    fn sd_bus_message_exit_container(message: *mut SdBusMessage) -> c_int;
    fn sd_bus_message_skip(message: *mut SdBusMessage, types: *const c_char) -> c_int;
    fn sd_bus_message_at_end(message: *mut SdBusMessage, complete: c_int) -> c_int;
}

fn check(code: c_int) -> io::Result<c_int> {
    if code < 0 {
        Err(io::Error::from_raw_os_error(-code))
    } else {
        Ok(code)
    }
}

fn read(code: c_int) -> io::Result<()> {
    if check(code)? == 0 {
        return Err(invalid("incomplete fwupd D-Bus reply"));
    }
    Ok(())
}

pub(super) struct Bus(NonNull<SdBus>);

impl Drop for Bus {
    fn drop(&mut self) {
        // This wrapper owns one sd-bus reference.
        unsafe { sd_bus_unref(self.0.as_ptr()) };
    }
}

impl Bus {
    pub(super) fn connect(address: &CStr) -> Result<Self> {
        let mut ptr = ptr::null_mut();
        // sd_bus_new assigns the sole reference on success.
        check(unsafe { sd_bus_new(&mut ptr) })?;
        let bus = Self(NonNull::new(ptr).ok_or_else(|| invalid("sd-bus returned no connection"))?);
        // The object is newly allocated and all string inputs are NUL terminated.
        unsafe {
            check(sd_bus_set_address(bus.0.as_ptr(), address.as_ptr()))?;
            check(sd_bus_set_bus_client(bus.0.as_ptr(), 1))?;
            check(sd_bus_negotiate_fds(bus.0.as_ptr(), 1))?;
            check(sd_bus_start(bus.0.as_ptr()))?;
        }
        Ok(bus)
    }

    pub(super) fn call(
        &self,
        destination: &CStr,
        path: &CStr,
        interface: &CStr,
        member: &CStr,
        args: &[&CStr],
    ) -> Result<Message> {
        let call = self.prepare(destination, path, interface, member)?;
        for value in args {
            call.append(b's', value.as_ptr().cast())?;
        }
        self.send(&call, CALL_TIMEOUT)
    }

    pub(super) fn import_lvfs(
        &self,
        owner: &CStr,
        metadata: BorrowedFd<'_>,
        signature: BorrowedFd<'_>,
    ) -> Result<()> {
        let call = self.prepare(owner, c"/", c"org.freedesktop.fwupd", c"UpdateMetadata")?;
        call.append(b's', c"lvfs".as_ptr().cast())?;
        for fd in [metadata, signature] {
            call.append_fd(fd)?;
        }
        self.send(&call, CATALOG_TIMEOUT)?.finish()
    }

    pub(super) fn verify_cabinet(
        &self,
        owner: &CStr,
        identity: [&CStr; 8],
        versions_raw: [u32; 2],
        cabinet: BorrowedFd<'_>,
    ) -> Result<(u64, bool)> {
        let call = self.prepare(owner, c"/", c"org.freedesktop.fwupd", c"VerifyFvcaCabinet")?;
        for value in identity {
            call.append(b's', value.as_ptr().cast())?;
        }
        for value in &versions_raw {
            call.append(b'u', std::ptr::from_ref(value).cast())?;
        }
        call.append_fd(cabinet)?;
        let mut reply = self.send(&call, CABINET_TIMEOUT)?;
        let bytes = reply.u64()?;
        let capsule_on_disk = reply.boolean()?;
        reply.finish()?;
        Ok((bytes, capsule_on_disk))
    }

    pub(super) fn stage_capsule(
        &self,
        owner: &CStr,
        identity: [&CStr; 8],
        operation: [&CStr; 2],
        versions_raw: [u32; 2],
        cabinet: BorrowedFd<'_>,
        lease: BorrowedFd<'_>,
    ) -> Result<()> {
        let call = self.prepare(owner, c"/", c"org.freedesktop.fwupd", c"StageFvcaCapsule")?;
        for value in identity.into_iter().chain(operation) {
            call.append(b's', value.as_ptr().cast())?;
        }
        for value in &versions_raw {
            call.append(b'u', std::ptr::from_ref(value).cast())?;
        }
        call.append_fd(cabinet)?;
        call.append_fd(lease)?;
        self.send(&call, CABINET_TIMEOUT)?.finish()
    }

    fn prepare(
        &self,
        destination: &CStr,
        path: &CStr,
        interface: &CStr,
        member: &CStr,
    ) -> Result<Message> {
        let mut ptr = ptr::null_mut();
        // The connection and the descriptor strings outlive this call.
        check(unsafe {
            sd_bus_message_new_method_call(
                self.0.as_ptr(),
                &mut ptr,
                destination.as_ptr(),
                path.as_ptr(),
                interface.as_ptr(),
                member.as_ptr(),
            )
        })?;
        let call = Message::owned(ptr)?;
        // Never activate a different peer while constructing a call.
        check(unsafe { sd_bus_message_set_auto_start(call.0.as_ptr(), 0) })?;
        Ok(call)
    }

    fn send(&self, call: &Message, timeout: u64) -> Result<Message> {
        let mut reply = ptr::null_mut();
        // Success transfers one reply reference.
        check(unsafe {
            sd_bus_call(
                self.0.as_ptr(),
                call.0.as_ptr(),
                timeout,
                ptr::null_mut(),
                &mut reply,
            )
        })?;
        Message::owned(reply)
    }
}

pub(super) struct Message(NonNull<SdBusMessage>);

impl Drop for Message {
    fn drop(&mut self) {
        // This wrapper owns one message reference, including any borrowed strings.
        unsafe { sd_bus_message_unref(self.0.as_ptr()) };
    }
}

impl Message {
    fn owned(ptr: *mut SdBusMessage) -> Result<Self> {
        Ok(Self(
            NonNull::new(ptr).ok_or_else(|| invalid("sd-bus returned no message"))?,
        ))
    }

    fn append(&self, kind: u8, value: *const c_void) -> io::Result<()> {
        // Private callers provide a NUL-terminated string or a pointer to the matching scalar type.
        check(unsafe { sd_bus_message_append_basic(self.0.as_ptr(), kind as c_char, value) })?;
        Ok(())
    }

    fn append_fd(&self, fd: BorrowedFd<'_>) -> io::Result<()> {
        // sd-bus duplicates the descriptor before the stack value and borrow expire.
        self.append(b'h', std::ptr::from_ref(&fd.as_raw_fd()).cast())
    }

    pub(super) fn string(&mut self) -> Result<String> {
        let mut value: *const c_char = ptr::null();
        // A D-Bus string is read into a const char pointer owned by the message.
        read(unsafe {
            sd_bus_message_read_basic(
                self.0.as_ptr(),
                b's' as c_char,
                (&mut value as *mut *const c_char).cast(),
            )
        })?;
        if value.is_null() {
            return Err(invalid("fwupd returned a missing D-Bus string").into());
        }
        // Copy the validated C string before another cursor operation.
        let text = unsafe { CStr::from_ptr(value) }.to_str()?;
        if text.len() > STR_LIMIT {
            return Err(invalid("fwupd D-Bus string exceeds its size bound").into());
        }
        Ok(text.into())
    }

    pub(super) fn u32(&mut self) -> Result<u32> {
        let mut value = 0u32;
        // Type u takes a pointer to uint32_t.
        read(unsafe {
            sd_bus_message_read_basic(
                self.0.as_ptr(),
                b'u' as c_char,
                (&mut value as *mut u32).cast(),
            )
        })?;
        Ok(value)
    }

    pub(super) fn u64(&mut self) -> Result<u64> {
        let mut value = 0u64;
        // Type t takes a pointer to uint64_t.
        read(unsafe {
            sd_bus_message_read_basic(
                self.0.as_ptr(),
                b't' as c_char,
                (&mut value as *mut u64).cast(),
            )
        })?;
        Ok(value)
    }

    pub(super) fn boolean(&mut self) -> Result<bool> {
        let mut value: c_int = 0;
        // sd-bus writes D-Bus booleans into an int, not a Rust bool.
        read(unsafe {
            sd_bus_message_read_basic(
                self.0.as_ptr(),
                b'b' as c_char,
                (&mut value as *mut c_int).cast(),
            )
        })?;
        Ok(value != 0)
    }

    fn enter(&mut self, kind: u8, contents: &CStr) -> io::Result<()> {
        // The signature and message are alive for this cursor operation.
        read(unsafe {
            sd_bus_message_enter_container(self.0.as_ptr(), kind as c_char, contents.as_ptr())
        })
    }

    fn exit(&mut self) -> io::Result<()> {
        // sd-bus refuses exit if a container was not fully consumed.
        check(unsafe { sd_bus_message_exit_container(self.0.as_ptr()) })?;
        Ok(())
    }

    pub(super) fn finish(&mut self) -> Result<()> {
        if !self.at_end(true)? {
            return Err(invalid("unexpected values at the end of the fwupd D-Bus reply").into());
        }
        Ok(())
    }

    fn at_end(&mut self, complete: bool) -> io::Result<bool> {
        // The message remains live at its current cursor position.
        Ok(check(unsafe { sd_bus_message_at_end(self.0.as_ptr(), c_int::from(complete)) })? != 0)
    }

    pub(super) fn variant<T>(
        &mut self,
        kind: &CStr,
        parse: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        self.enter(b'v', kind)?;
        let value = parse(self)?;
        self.exit()?;
        Ok(value)
    }

    pub(super) fn skip_variant(&mut self) -> Result<()> {
        // Skip a fully typed variant without converting unknown values.
        read(unsafe { sd_bus_message_skip(self.0.as_ptr(), c"v".as_ptr()) })?;
        Ok(())
    }

    pub(super) fn array<T>(
        &mut self,
        contents: &CStr,
        mut parse: impl FnMut(&mut Self) -> Result<T>,
    ) -> Result<Vec<T>> {
        self.enter(b'a', contents)?;
        let mut values = Vec::new();
        while !self.at_end(false)? {
            if values.len() == ITEM_LIMIT {
                return Err(invalid("fwupd D-Bus array exceeds its item bound").into());
            }
            values.push(parse(self)?);
        }
        self.exit()?;
        Ok(values)
    }

    pub(super) fn dictionary(
        &mut self,
        mut parse: impl FnMut(&str, &mut Self) -> Result<()>,
    ) -> Result<()> {
        self.enter(b'a', c"{sv}")?;
        let mut keys = std::collections::HashSet::new();
        while !self.at_end(false)? {
            self.enter(b'e', c"sv")?;
            let key = self.string()?;
            if keys.len() == ITEM_LIMIT || !keys.insert(key.clone()) {
                return Err(invalid("duplicate or excessive fwupd D-Bus properties").into());
            }
            parse(&key, self)?;
            self.exit()?;
        }
        self.exit()?;
        Ok(())
    }
}
