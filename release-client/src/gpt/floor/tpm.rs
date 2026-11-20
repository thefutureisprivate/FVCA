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

impl Tpm {
    pub(super) fn open(policy: &[u8; 32]) -> io::Result<Self> {
        #[cfg(feature = "swtpm-test")]
        let test_transport = {
            let location = std::env::var("FVCA_TEST_SWTPM_SOCKET").map_err(io::Error::other)?;
            if !location.starts_with('/') || location.contains(',') {
                return Err(io::Error::other(
                    "expected an absolute disposable software TPM socket",
                ));
            }
            std::ffi::CString::new(format!("swtpm:path={location}")).map_err(io::Error::other)?
        };
        #[cfg(feature = "swtpm-test")]
        let transport = test_transport.as_c_str();
        #[cfg(not(feature = "swtpm-test"))]
        let transport = c"device:/dev/tpmrm0";

        let mut context = ptr::null_mut();
        let mut name = [0u8; 34];
        // The pointers refer to a NUL-terminated string, fixed arrays and a writable
        // out-pointer. Success transfers exclusive ownership of the C allocation.
        let status = unsafe {
            fvca_floor_open(
                transport.as_ptr(),
                policy.as_ptr(),
                &mut context,
                name.as_mut_ptr(),
            )
        };
        checked(status, "verify the enrolled floor counter")?;
        let context =
            NonNull::new(context).ok_or_else(|| io::Error::other("missing TPM context"))?;
        // cpHash is H(NV_Increment || Name(authHandle) || Name(nvIndex)). Both
        // handles refer to the enrolled NV index and there are no parameters.
        let mut hash = Sha256::new();
        hash.update(0x134u32.to_be_bytes());
        hash.update(name);
        hash.update(name);
        Ok(Self {
            context,
            command: hash.finalize().into(),
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
        let mut message = nonce.to_vec();
        message.extend(seconds.to_be_bytes());
        message.extend(self.command);
        message.extend(reference);
        Ok(message)
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

impl Drop for Tpm {
    fn drop(&mut self) {
        // Ownership is unique and transferred back to C exactly once.
        unsafe { fvca_floor_close(self.context.as_ptr()) };
    }
}
