//! Exact launch selection authenticated by the Hypervisor UKI.

use std::fs;
use std::io::{self, Read, Write};
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
const COMMISSIONING: &str = "/usr/lib/fvca/guest-commissioning";
pub const COMMISSIONING_RUNTIME: &str = "/run/fvca/guest-commissioning";

pub struct Commissioning<'a> {
    pub bundle: &'a str,
    pub bytes: u64,
    pub digest: &'a str,
}

impl<'a> Commissioning<'a> {
    pub fn parse(text: &'a str) -> io::Result<Self> {
        let invalid_record = || invalid("invalid signed Service Guest commissioning record");
        let mut lines = text.split_terminator('\n');
        if !text.ends_with('\n') || lines.next() != Some("FVCA-GUEST-COMMISSIONING-1")
            || lines.next().and_then(|line| line.strip_prefix("guest=")).map(str::as_bytes)
                != Some(SERVICE_GUEST_UUID.to_bytes())
        {
            return Err(invalid_record());
        }
        let mut field = |prefix| lines.next().and_then(|line| line.strip_prefix(prefix)).ok_or_else(invalid_record);
        let bundle = runtime::hash(field("bundle=")?)?;
        let size = field("bytes=")?;
        let bytes = size.parse::<u64>().map_err(|_| invalid_record())?;
        let digest = runtime::hash(field("seed_sha256=")?)?;
        if lines.next().is_some() || size != bytes.to_string() || bytes == 0 || bytes > i64::MAX as u64
            || !bytes.is_multiple_of(512)
        {
            return Err(invalid_record());
        }
        Ok(Self { bundle, bytes, digest })
    }
}

pub fn publish_commissioning(bundle: Option<&str>, authenticated: bool) -> io::Result<()> {
    let file = match fs::File::open(COMMISSIONING) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        result => result?,
    };
    let mut text = String::new();
    file.take(512).read_to_string(&mut text)?;
    let selection = Commissioning::parse(&text)?;
    if text.len() == 512 || !authenticated || bundle != Some(selection.bundle) {
        return Err(invalid("commissioning requires the selected Guest and authenticated Host storage"));
    }
    fs::OpenOptions::new().create_new(true).write(true).mode(0o600)
        .open(COMMISSIONING_RUNTIME)?.write_all(text.as_bytes())?;
    let dropin = Path::new("/run/systemd/system/fvca-service-guest.service.d");
    fs::create_dir_all(dropin)?;
    fs::write(
        dropin.join("10-commissioning.conf"),
        "[Unit]\nRequires=fvca-commission-guest.service\nAfter=fvca-commission-guest.service\n",
    )
}

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

pub enum Startup {
    Automatic,
    AfterFirmwareRecovery,
    Disabled,
}

pub fn activate_if_selected(
    startup: Startup,
    devices: Option<&(PathBuf, PathBuf)>,
    cmdline: &str,
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
    crate::host_workload::guest_mac(&fs::read_to_string(Path::new(BOOT).join("cmdline"))?)?;
    let bundle = selection.bundle.to_owned();
    fs::write(SELECTION, payload)?;
    crate::guest_resources::publish(cmdline)?;
    if matches!(startup, Startup::Disabled) {
        return Ok(Some(bundle));
    }
    publish_trial_enrollment()?;
    let control = Path::new("/run/systemd/system");
    if matches!(startup, Startup::AfterFirmwareRecovery) {
        let dropin = control.join("fvca-firmware-recovery.service.d");
        fs::create_dir_all(&dropin)?;
        fs::write(
            dropin.join("30-resume-guest.conf"),
            "[Unit]\nOnSuccess=fvca-service-guest.service\n",
        )?;
        return Ok(Some(bundle));
    }
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
