//! Use the system libcrypto's one-shot Ed25519 verifier with a raw public key.

use std::ffi::{c_char, c_int, c_void};
use std::io;
use std::ptr::{NonNull, null, null_mut};

#[link(name = "crypto")]
unsafe extern "C" {
    fn EVP_PKEY_new_raw_public_key_ex(
        context: *mut c_void,
        key_type: *const c_char,
        properties: *const c_char,
        key: *const u8,
        length: usize,
    ) -> *mut c_void;
    fn EVP_PKEY_free(key: *mut c_void);
    fn EVP_MD_CTX_new() -> *mut c_void;
    fn EVP_MD_CTX_free(context: *mut c_void);
    fn EVP_DigestVerifyInit(
        context: *mut c_void,
        key_context: *mut *mut c_void,
        digest: *const c_void,
        engine: *mut c_void,
        key: *mut c_void,
    ) -> c_int;
    fn EVP_DigestVerify(
        context: *mut c_void,
        signature: *const u8,
        signature_length: usize,
        message: *const u8,
        message_length: usize,
    ) -> c_int;
}

struct Key(NonNull<c_void>);

impl Drop for Key {
    fn drop(&mut self) {
        // This wrapper owns the live, non-null EVP_PKEY returned by libcrypto.
        unsafe { EVP_PKEY_free(self.0.as_ptr()) }
    }
}

struct Context(NonNull<c_void>);

impl Drop for Context {
    fn drop(&mut self) {
        // This wrapper owns the live, non-null EVP_MD_CTX returned by libcrypto.
        unsafe { EVP_MD_CTX_free(self.0.as_ptr()) }
    }
}

pub fn verify_ed25519(key: &[u8; 32], signature: &[u8; 64], message: &[u8]) -> io::Result<()> {
    // libcrypto copies the fixed-width raw key. Use the default library context.
    let key = unsafe {
        EVP_PKEY_new_raw_public_key_ex(
            null_mut(),
            c"ED25519".as_ptr(),
            null(),
            key.as_ptr(),
            key.len(),
        )
    };
    let key =
        Key(NonNull::new(key)
            .ok_or_else(|| io::Error::other("could not load the Ed25519 approval key"))?);
    // The returned context is independently owned and drops before the key.
    let context = Context(
        NonNull::new(unsafe { EVP_MD_CTX_new() })
            .ok_or_else(|| io::Error::other("could not allocate a signature verifier"))?,
    );
    // Pure Ed25519 uses no separate digest or engine. Both handles remain live.
    if unsafe {
        EVP_DigestVerifyInit(
            context.0.as_ptr(),
            null_mut(),
            null(),
            null_mut(),
            key.0.as_ptr(),
        )
    } != 1
    {
        return Err(io::Error::other(
            "could not initialize the Ed25519 signature verifier",
        ));
    }
    // The input slices stay live and immutable for the duration of the one-shot call.
    if unsafe {
        EVP_DigestVerify(
            context.0.as_ptr(),
            signature.as_ptr(),
            signature.len(),
            message.as_ptr(),
            message.len(),
        )
    } != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Ed25519 signature verification failed",
        ));
    }
    Ok(())
}
