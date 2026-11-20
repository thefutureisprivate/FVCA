//! Persistent firmware activation fence shared across Host boots and services.

use std::fs;
use std::io;
use std::path::Path;

pub const STATE_DIRECTORY: &str = "firmware-update";
pub const ACTIVATION: &str = "activation.json";
const HOST_DATA: &str = "/run/fvca/host-data";

pub fn activation_pending() -> io::Result<bool> {
    let path = Path::new(HOST_DATA).join(STATE_DIRECTORY).join(ACTIVATION);
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

pub fn require_idle() -> io::Result<()> {
    if activation_pending()? {
        return Err(crate::invalid(
            "a Host firmware activation requires reconciliation",
        ));
    }
    Ok(())
}
