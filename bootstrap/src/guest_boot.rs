//! Exact launch selection authenticated by the Hypervisor UKI.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub use fvca_trial_authorization::guest::{
    BOOT, FILES, SELECTION, SERVICE_GUEST_UUID, Selection, TRIAL_ENROLLMENT, parse,
};

use crate::{invalid, runtime};

const SOURCE: &str = "/usr/lib/fvca/guest-launch";
const SIGNATURE: &str = "/usr/lib/fvca/guest-launch.p7s";
const TRIAL_KEY: &str = "/usr/lib/fvca/guest-trial-key";
const BASE_EPOCH: &str = "/usr/lib/fvca/guest-base-epoch";

fn publish_trial_enrollment() -> io::Result<()> {
    let authority = match fs::read(TRIAL_KEY) {
        Err(error)
            if error.kind() == io::ErrorKind::NotFound
                && !Path::new(BASE_EPOCH).try_exists()? =>
        {
            return Ok(());
        }
        result => result?,
    };
    if authority.len() != 32 {
        return Err(invalid("invalid signed Guest trial authority"));
    }
    let enrolled = [authority, fs::read(BASE_EPOCH)?].concat();
    fvca_trial_authorization::guest::enrollment(&enrolled)?;
    fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(TRIAL_ENROLLMENT)?
        .write_all(&enrolled)
}

pub fn activate_if_selected(
    auto_start: bool,
    devices: Option<&(PathBuf, PathBuf)>,
) -> io::Result<Option<String>> {
    let payload = match fs::read_to_string(SOURCE) {
        Ok(payload) => payload,
        Err(error)
            if error.kind() == io::ErrorKind::NotFound && !Path::new(SIGNATURE).try_exists()? =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let selection = parse(&payload)?;
    runtime::mount_verified(
        "guest-boot",
        "Guest boot bundle",
        selection.bundle,
        Path::new(SIGNATURE),
        Path::new(BOOT),
        "ro,nodev,nosuid,noexec",
        devices,
    )?;
    let bundle = selection.bundle.to_owned();
    fs::write(SELECTION, payload)?;
    if !auto_start {
        return Ok(Some(bundle));
    }
    publish_trial_enrollment()?;
    let control = Path::new("/run/systemd/system");
    let dropin = control.join("fvca-base-ready.service.d");
    let wants = control.join("fvca-base-ready.service.wants");
    fs::create_dir_all(&dropin)?;
    fs::create_dir_all(&wants)?;
    fs::write(
        dropin.join("20-guest-ready.conf"),
        concat!(
            "[Service]\n",
            "ExecStartPre=/usr/bin/systemctl --quiet is-active fvca-service-guest.service\n",
        ),
    )?;
    std::os::unix::fs::symlink(
        "/usr/lib/systemd/system/fvca-service-guest.service",
        wants.join("fvca-service-guest.service"),
    )?;
    Ok(Some(bundle))
}
