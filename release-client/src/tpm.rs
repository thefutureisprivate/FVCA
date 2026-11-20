use std::ffi::CStr;
use std::io;

pub fn with_transport<T>(call: impl FnOnce(&CStr) -> T) -> io::Result<T> {
    #[cfg(feature = "swtpm-test")]
    let test_transport = {
        let location = std::env::var("FVCA_TEST_SWTPM_SOCKET").map_err(io::Error::other)?;
        if !location.starts_with('/') || location.contains(',') {
            return Err(crate::invalid(
                "expected an absolute disposable software TPM socket",
            ));
        }
        std::ffi::CString::new(format!("swtpm:path={location}")).map_err(io::Error::other)?
    };
    #[cfg(feature = "swtpm-test")]
    let transport = test_transport.as_c_str();
    #[cfg(not(feature = "swtpm-test"))]
    let transport = c"device:/dev/tpmrm0";
    Ok(call(transport))
}
