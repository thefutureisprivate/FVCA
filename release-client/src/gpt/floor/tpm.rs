//! Owns one native ESAPI context and its TPM handles for the entire transaction.

use std::ffi::{c_char, c_void};
use std::io;
use std::ptr::{self, NonNull};

use sha2::{Digest, Sha256};

unsafe extern "C" {
    fn fvca_floor_open(
        transport: *const c_char,
        policy: *const u8,
        out: *mut *mut c_void,
        name: *mut u8,
    ) -> u32;
    fn fvca_floor_close(tpm: *mut c_void);
    fn fvca_floor_read(tpm: *mut c_void, out: *mut u64) -> u32;
    fn fvca_floor_begin(
        tpm: *mut c_void,
        key: *const u8,
        key_bytes: usize,
        reference: *const u8,
        command: *const u8,
        nonce: *mut u8,
    ) -> u32;
    fn fvca_floor_authorize(tpm: *mut c_void, seconds: u32, signature: *const u8) -> u32;
    fn fvca_floor_increment(tpm: *mut c_void) -> u32;
    #[cfg(not(feature = "appliance"))]
    fn fvca_floor_prepare(
        transport: *const c_char,
        key: *const u8,
        key_bytes: usize,
        reference: *const u8,
        out: *mut *mut c_void,
        digest: *mut u8,
        identity: *mut u8,
    ) -> u32;
    #[cfg(not(feature = "appliance"))]
    fn fvca_floor_probe(tpm: *mut c_void, state: *mut u32, name: *mut u8) -> u32;
    #[cfg(not(feature = "appliance"))]
    fn fvca_floor_define(tpm: *mut c_void, owner: *const u8) -> u32;
    #[cfg(not(feature = "appliance"))]
    fn fvca_floor_begin_prepared(tpm: *mut c_void, command: *const u8, nonce: *mut u8) -> u32;
}

pub(super) struct Tpm {
    context: NonNull<c_void>,
    command: [u8; 32],
}

fn checked(code: u32, action: &str) -> io::Result<()> {
    if code != 0 {
        return Err(io::Error::other(format!(
            "TPM could not {action} (0x{code:08x})"
        )));
    }
    Ok(())
}

fn command_hash(name: &[u8; 34]) -> [u8; 32] {
    // cpHash is H(NV_Increment || Name(authHandle) || Name(nvIndex)). Both
    // handles refer to the same counter and there are no parameters.
    let mut hash = Sha256::new();
    hash.update(0x134u32.to_be_bytes());
    hash.update(name);
    hash.update(name);
    hash.finalize().into()
}

impl Tpm {
    pub(super) fn open(policy: &[u8; 32]) -> io::Result<Self> {
        let mut context = ptr::null_mut();
        let mut name = [0u8; 34];
        // The pointers refer to a NUL-terminated string, fixed arrays and a writable
        // out-pointer. Success transfers exclusive ownership of the C allocation.
        let status = crate::tpm::with_transport(|transport| unsafe {
            fvca_floor_open(
                transport.as_ptr(),
                policy.as_ptr(),
                &mut context,
                name.as_mut_ptr(),
            )
        })?;
        checked(status, "verify the enrolled floor counter")?;
        let context =
            NonNull::new(context).ok_or_else(|| io::Error::other("missing TPM context"))?;
        Ok(Self {
            context,
            command: command_hash(&name),
        })
    }

    pub(super) fn read(&mut self) -> io::Result<u64> {
        let mut value = 0;
        // The context is owned by self and value is writable for the call.
        let status = unsafe { fvca_floor_read(self.context.as_ptr(), &mut value) };
        checked(status, "read the floor counter")?;
        Ok(value)
    }

    pub(super) fn challenge(
        &mut self,
        key: &[u8],
        reference: &[u8; 40],
        seconds: u32,
    ) -> io::Result<Vec<u8>> {
        let mut nonce = [0u8; 32];
        // The key length and fixed array pointers describe live buffers; C
        // copies the values it needs and owns the temporary TPM session.
        let status = unsafe {
            fvca_floor_begin(
                self.context.as_ptr(),
                key.as_ptr(),
                key.len(),
                reference.as_ptr(),
                self.command.as_ptr(),
                nonce.as_mut_ptr(),
            )
        };
        checked(
            status,
            "start a session for the enrolled increment authority",
        )?;
        Ok(self.message(&nonce, reference, seconds))
    }

    fn message(&self, nonce: &[u8; 32], reference: &[u8; 40], seconds: u32) -> Vec<u8> {
        let mut message = nonce.to_vec();
        message.extend(seconds.to_be_bytes());
        message.extend(self.command);
        message.extend(reference);
        message
    }

    pub(super) fn authorize(&mut self, seconds: u32, signature: &[u8; 64]) -> io::Result<()> {
        // The context is exclusively borrowed and signature has the required width.
        let status =
            unsafe { fvca_floor_authorize(self.context.as_ptr(), seconds, signature.as_ptr()) };
        checked(status, "authorize the live session signature")
    }

    pub(super) fn increment(&mut self) -> io::Result<()> {
        // The context is exclusively borrowed for the native call.
        let status = unsafe { fvca_floor_increment(self.context.as_ptr()) };
        checked(status, "increment the enrolled floor counter")
    }
}

#[cfg(not(feature = "appliance"))]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Counter {
    Absent,
    Uninitialized,
    Initialized,
}

#[cfg(not(feature = "appliance"))]
impl Tpm {
    pub(super) fn prepare(
        key: &[u8],
        reference: &[u8; 40],
    ) -> io::Result<(Self, [u8; 32], [u8; 34])> {
        let mut context = ptr::null_mut();
        let mut policy = [0; 32];
        let mut identity = [0; 34];
        // Success transfers one allocation. The buffers have the widths
        // required by the bridge and the key input has an explicit length.
        let status = crate::tpm::with_transport(|transport| unsafe {
            fvca_floor_prepare(
                transport.as_ptr(),
                key.as_ptr(),
                key.len(),
                reference.as_ptr(),
                &mut context,
                policy.as_mut_ptr(),
                identity.as_mut_ptr(),
            )
        })?;
        checked(
            status,
            "inspect the floor enrollment identity and authority policy",
        )?;
        let context =
            NonNull::new(context).ok_or_else(|| io::Error::other("missing TPM context"))?;
        Ok((
            Self {
                context,
                command: [0; 32],
            },
            policy,
            identity,
        ))
    }

    pub(super) fn probe(&mut self) -> io::Result<Counter> {
        let mut state = 0;
        let mut name = [0; 34];
        // The handle is exclusively borrowed and both output buffers are live.
        let status =
            unsafe { fvca_floor_probe(self.context.as_ptr(), &mut state, name.as_mut_ptr()) };
        checked(status, "verify the reserved floor counter's public area")?;
        match state {
            0 => Ok(Counter::Absent),
            initialized @ (1 | 2) => {
                self.command = command_hash(&name);
                Ok(if initialized == 1 {
                    Counter::Uninitialized
                } else {
                    Counter::Initialized
                })
            }
            _ => Err(io::Error::other("unexpected floor enrollment state")),
        }
    }

    pub(super) fn define(&mut self, owner: &[u8; 32]) -> io::Result<()> {
        // The bridge receives a fixed-width credential and clears its copy.
        let status = unsafe { fvca_floor_define(self.context.as_ptr(), owner.as_ptr()) };
        checked(status, "define the owner-authorized floor counter")
    }

    pub(super) fn initial_challenge(
        &mut self,
        reference: &[u8; 40],
        seconds: u32,
    ) -> io::Result<Vec<u8>> {
        let mut nonce = [0; 32];
        // Probe has computed the command hash for the defined, unwritten
        // index. The bridge retains this hash and the live policy session.
        let status = unsafe {
            fvca_floor_begin_prepared(
                self.context.as_ptr(),
                self.command.as_ptr(),
                nonce.as_mut_ptr(),
            )
        };
        checked(status, "start the initial floor authorization session")?;
        Ok(self.message(&nonce, reference, seconds))
    }
}

impl Drop for Tpm {
    fn drop(&mut self) {
        // Ownership is unique and transferred back to C exactly once.
        unsafe { fvca_floor_close(self.context.as_ptr()) };
    }
}
