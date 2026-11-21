//! Exact launch selection authenticated by the Hypervisor UKI.

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use fvca_trial_authorization::{commissioning, guest_config};
pub use fvca_trial_authorization::commissioning::Seed as Commissioning;
pub use fvca_trial_authorization::guest::{
    BOOT, FILES, SELECTION, SERVICE_GUEST_UUID, Selection, TRIAL_ENROLLMENT, parse,
};

use crate::{invalid, runtime};

const SOURCE: &str = "/usr/lib/fvca/guest-launch";
const SIGNATURE: &str = "/usr/lib/fvca/guest-launch.p7s";
const TRIAL_KEY: &str = "/usr/lib/fvca/guest-trial-key";
const BASE_EPOCH: &str = "/usr/lib/fvca/guest-base-epoch";
const COMMISSIONING: &str = "/usr/lib/fvca/guest-commissioning";
const MANAGED: &str = "/usr/lib/fvca/guest-commissioning-managed";
const PROVISIONING_POLICY: &str = "/usr/lib/fvca/guest-provisioning-policy-v1";
const CONTROL: &str = "/run/systemd/system";
const DISPATCH: &str = "fvca-commissioning-dispatch.path";

fn publish_private(path: &str, data: &str) -> io::Result<()> {
    fs::OpenOptions::new().create_new(true).write(true).mode(0o600)
        .open(path)?.write_all(data.as_bytes())
}

pub fn managed_commissioning() -> io::Result<bool> {
    Path::new(MANAGED).try_exists()
}

pub fn publish_commissioning(bundle: Option<&str>, authenticated: bool, cmdline: &str) -> io::Result<()> {
    let file = match fs::File::open(COMMISSIONING) {
        Err(error) if error.kind() == io::ErrorKind::NotFound && !managed_commissioning()? => return Ok(()),
        result => result?,
    };
    let mut text = String::new();
    file.take(commissioning::LIMIT as u64 + 1).read_to_string(&mut text)?;
    let selection = Commissioning::parse(&text)?;
    if text.len() > commissioning::LIMIT || !authenticated || bundle != Some(selection.bundle) {
        return Err(invalid("commissioning requires the selected Guest and authenticated Host storage"));
    }
    publish_private(commissioning::SELECTION, &text)?;
    let control = Path::new(CONTROL);
    let dropin = control.join("fvca-service-guest.service.d");
    fs::create_dir_all(&dropin)?;
    fs::write(
        dropin.join("10-commissioning.conf"),
        "[Unit]\nRequires=fvca-commission-guest.service\nAfter=fvca-commission-guest.service\n",
    )?;
    if managed_commissioning()? {
        let marker = fs::symlink_metadata(PROVISIONING_POLICY)?;
        if !marker.is_file() || marker.len() != 0 {
            return Err(invalid("the verified Host lacks the provisioning watch policy"));
        }
        let mut host = String::new();
        fs::File::open(MANAGED)?.take(38).read_to_string(&mut host)?;
        let host = host.strip_suffix('\n').ok_or_else(|| invalid("invalid provisioning enrollment"))?;
        let binding = guest_config::binding(cmdline)?;
        let offer = commissioning::Offer::record(host, binding.as_ref(), crate::guest_resources::active()?, &text)?;
        publish_private(commissioning::OFFER, &offer)?;
        let wants = control.join("fvca-base.target.wants");
        fs::create_dir_all(&wants)?;
        symlink(format!("/usr/lib/systemd/system/{DISPATCH}"), wants.join(DISPATCH))?;
        let broker = control.join("fvca-management-broker.service.d");
        fs::create_dir_all(&broker)?;
        fs::write(broker.join("30-provisioning.conf"), format!("[Unit]\nRequires={DISPATCH}\nAfter={DISPATCH}\n"))?;
    }
    Ok(())
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
    AwaitProvisioning,
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
    if matches!(startup, Startup::AwaitProvisioning) {
        return Ok(Some(bundle));
    }
    let control = Path::new(CONTROL);
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
    symlink(
        "/usr/lib/systemd/system/fvca-service-guest.service",
        wants.join("fvca-service-guest.service"),
    )?;
    Ok(Some(bundle))
}
