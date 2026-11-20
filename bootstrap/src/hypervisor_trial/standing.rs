//! Verify an off-node trial authorization against the booted release.

use std::io::{self, Read};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use fvca_trial_authorization::{Standing, guest_config};

use super::{gpt_device, promotion, publish, read_record, verify_signature};
use crate::{HYPERVISOR_EPOCH_ARGUMENT, invalid, runtime};

pub(super) fn verify(envelope: &[u8]) -> io::Result<Standing<'_>> {
    Standing::parse(verify_signature("trial", envelope)?)
}

pub(super) fn require_epoch(
    approval: &Standing<'_>,
    marker: Option<&str>,
    expected: u64,
) -> io::Result<()> {
    let value = format!(
        "{HYPERVISOR_EPOCH_ARGUMENT}={expected},{}",
        approval.epoch_policy
    );
    if marker != Some(value.as_str()) {
        return Err(invalid(
            "standing trial does not authorize this release epoch and enrollment",
        ));
    }
    Ok(())
}

pub(super) fn require_stable(
    approval: &Standing<'_>,
    active: &runtime::Activation,
    guest: Option<&str>,
    epoch: Option<&str>,
) -> io::Result<()> {
    if [
        Some(active.core.as_str()),
        Some(active.extension.as_str()),
        guest,
    ] != approval.stable_roots.map(Some)
    {
        return Err(invalid(
            "standing trial differs from the running stable composition",
        ));
    }
    require_epoch(approval, epoch, approval.stable_epoch)
}

pub(super) fn require_fresh(approval: &Standing<'_>) -> io::Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs();
    approval.require_fresh(now)
}

pub(super) fn require_guest_configuration(
    directory: &Path,
    transaction: &str,
    cmdline: &str,
    reserve: bool,
) -> io::Result<()> {
    let record = directory.join(format!("{transaction}.guest-configuration"));
    let expected = match guest_config::binding(cmdline)? {
        Some(binding) => format!("{},{}\n", binding.revision, binding.sha256),
        None => "profile-default\n".to_owned(),
    };
    match read_record(&record) {
        Ok(previous) if previous == expected.as_bytes() => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound && reserve => {
            publish(&record, expected.as_bytes())
        }
        Ok(_) => Err(invalid(
            "standing Host trial changes the stable Guest configuration",
        )),
        Err(error) => Err(error),
    }
}

pub(super) fn verify_candidate(approval: &Standing<'_>) -> io::Result<()> {
    let (device, size) = gpt_device(&approval.authorization.trial.candidate)?;
    if size != approval.authorization.bytes {
        return Err(invalid("standing trial candidate ESP geometry changed"));
    }
    verify_candidate_uki(&device, approval)?;
    promotion::verify_payloads(&device, approval.payloads, &approval.authorization)
}

fn verify_candidate_uki(device: &Path, approval: &Standing<'_>) -> io::Result<()> {
    let mut hash = Command::new("/usr/bin/sha256sum")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let loader = Command::new("/sysroot/usr/bin/mcopy")
        .env_clear()
        .env("MTOOLSRC", "/sysroot/usr/share/fvca/mtools.conf")
        .env("GCONV_PATH", "/sysroot/usr/lib64/fvca/fat-gconv")
        .arg("-i")
        .arg(device)
        .args(["::/EFI/BOOT/BOOTX64.EFI", "-"])
        .stdout(Stdio::piped())
        .spawn();
    let mut loader = match loader {
        Ok(loader) => loader,
        Err(error) => {
            let _ = hash.kill();
            let _ = hash.wait();
            return Err(error);
        }
    };
    let copied = io::copy(
        &mut loader
            .stdout
            .take()
            .expect("loader output is piped")
            .take(approval.candidate_uki_bytes + 1),
        &mut hash.stdin.take().expect("hash input is piped"),
    );
    let status = loader.wait()?;
    let digest = hash.wait_with_output()?;
    if copied? != approval.candidate_uki_bytes
        || !status.success()
        || !digest.status.success()
        || digest.stdout != format!("{}  -\n", approval.candidate_uki).as_bytes()
    {
        return Err(invalid(
            "installed candidate UKI differs from standing trial",
        ));
    }
    Ok(())
}
