//! Promote a healthy standing trial using the independently signed release grant.

use std::fs::{self, File};
use std::io;
use std::path::Path;
use std::process::Command;

use fvca_trial_authorization::{PROMOTED_RELEASE, Promotion};

use super::{
    PENDING, Trial, approved_evidence, boot_next, boot_order, gpt_device, promoted_order,
    promotion, publish, read_record, standing, verify_signature,
};
use crate::{invalid, run, runtime};

const RETURN: &str = "/run/fvca/standing-promotion";
const RETURN_UNIT: &str = concat!(
    "[Unit]\nDescription=Return from a healthy Hypervisor trial for promotion\n",
    "Requires=fvca-trial-health.service\nAfter=fvca-trial-health.service\n",
    "Before=fvca-base.target\n",
    "OnFailure=fvca-recover-hypervisor-activation.service\n",
    "[Service]\nType=oneshot\nTimeoutStartSec=60s\n",
    "SELinuxContext=system_u:system_r:init_t:s0\n",
    "ExecStart=/usr/libexec/fvca/launch-guest --return-healthy-hypervisor\n",
    "NoNewPrivileges=yes\nMemoryDenyWriteExecute=yes\n",
    "StandardOutput=journal+console\nStandardError=journal+console\n",
);

fn grant(directory: &Path, trial: &Trial<'_>) -> io::Result<Option<Vec<u8>>> {
    let path = directory.join(format!("{}.standing-promotion", trial.transaction));
    match read_record(&path) {
        Ok(packet) => Ok(Some(packet)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn require_payloads(promotion: &Promotion<'_>, ids: &[String; 6]) -> io::Result<()> {
    if !promotion
        .trial
        .payloads
        .iter()
        .flatten()
        .copied()
        .eq(ids.iter().map(String::as_str))
    {
        return Err(invalid(
            "standing promotion differs from the signed candidate partitions",
        ));
    }
    Ok(())
}

pub(super) fn enroll_return(
    directory: &Path,
    trial: &Trial<'_>,
    attempt: &[u8],
    ids: &[String; 6],
) -> io::Result<()> {
    let Some(packet) = grant(directory, trial)? else {
        return Ok(());
    };
    let body = verify_signature("promotion", &packet)?;
    let approval = Promotion::parse(body)?;
    approval.matches_trial(attempt)?;
    require_payloads(&approval, ids)?;
    standing::require_fresh(&approval.trial)?;
    publish(Path::new(RETURN), body.as_bytes())?;
    let units = Path::new("/run/systemd/system");
    let wants = units.join("fvca-base.target.wants");
    fs::create_dir_all(&wants)?;
    fs::write(units.join("fvca-trial-return.service"), RETURN_UNIT)?;
    std::os::unix::fs::symlink(
        "../fvca-trial-return.service",
        wants.join("fvca-trial-return.service"),
    )
}

#[cfg(feature = "promotion")]
pub fn healthy_return() -> io::Result<String> {
    let grant = read_record(Path::new(RETURN))?;
    let approval = Promotion::parse(std::str::from_utf8(&grant).map_err(io::Error::other)?)?;
    let trial = &approval.trial.authorization.trial;
    let directory = super::record_directory()?;
    let receipt = read_record(Path::new(super::STARTED))?;
    let healthy = read_record(&directory.join(format!("{}.healthy", trial.transaction)))?;
    let evidence = approved_evidence(&approval.trial.authorization, &healthy)?;
    if receipt != healthy
        || evidence.boot != super::boot_id()?
        || super::selected()? != trial.candidate.id
        || boot_next()?.is_some()
        || boot_order()?.get(..2) != Some(&[trial.stable.id, trial.candidate.id])
    {
        return Err(invalid(
            "promotion return requires the current healthy trial and its stable recovery entry",
        ));
    }
    standing::require_fresh(&approval.trial)?;
    gpt_device(&trial.stable)?;
    Ok(trial.transaction.into())
}

pub(super) fn commit(
    directory: &Path,
    attempt: &[u8],
    health: &[u8],
    order: &[u16],
) -> io::Result<bool> {
    let trial = standing::verify(attempt)?;
    let Some(packet) = grant(directory, &trial.authorization.trial)? else {
        return Ok(false);
    };
    let approval = Promotion::parse(verify_signature("promotion", &packet)?)?;
    approval.matches_trial(attempt)?;
    let trial = &approval.trial.authorization.trial;
    let tx = trial.transaction;
    let key = promotion::pinned_key()?.ok_or_else(|| invalid("no standing promotion authority"))?;
    if read_record(&directory.join(format!("{tx}.promotion-key")))? != key {
        return Err(invalid(
            "candidate did not pin the same standing promotion authority",
        ));
    }
    approved_evidence(&approval.trial.authorization, health)?;
    let wanted = promoted_order(order, trial.stable.id, trial.candidate.id)?;
    if boot_next()?.is_some() {
        return Err(invalid(
            "standing promotion cannot override a pending one-shot boot",
        ));
    }
    standing::verify_candidate(&approval.trial)?;
    standing::require_fresh(&approval.trial)?;
    let intent = directory.join(format!("{tx}.promotion-intent"));
    match publish(&intent, &packet) {
        Err(error)
            if error.kind() == io::ErrorKind::AlreadyExists && read_record(&intent)? == packet => {}
        result => result?,
    }
    run(Command::new("/usr/lib/fvca/set-boot-order")
        .arg(trial.stable.id.to_string())
        .arg(trial.candidate.id.to_string()))?;
    if boot_order()? != wanted {
        return Err(invalid(
            "firmware BootOrder differs from standing promotion",
        ));
    }
    println!("FVCA_BOOT_PROMOTED {tx}");
    Ok(true)
}

pub(super) fn authorize_boot(
    directory: &Path,
    trial: &Trial<'_>,
    guest: Option<&str>,
    active: &runtime::Activation,
    ids: &[String; 6],
    body: &str,
    default: bool,
) -> io::Result<()> {
    let promotion = Promotion::parse(body)?;
    let approved = &promotion.trial.authorization;
    let tx = trial.transaction;
    let attempt = read_record(&directory.join(tx))?;
    standing::verify(&attempt)?;
    promotion.matches_trial(&attempt)?;
    let number = super::attempts::last(directory, tx)?;
    if super::prior_health(directory, approved, number)?.is_none()
        || *trial != approved.trial
        || guest != Some(approved.guest)
        || active.core != approved.core
        || active.extension != approved.runtime
    {
        return Err(invalid(
            "default candidate differs from its standing promotion",
        ));
    }
    require_payloads(&promotion, ids)?;
    gpt_device(&trial.candidate)?;
    let confirmed = directory.join(format!("{tx}.promotion-confirmed"));
    if !default {
        if read_record(&confirmed)? != body.as_bytes() {
            return Err(invalid(
                "fallback Hypervisor lacks a previously confirmed standing promotion",
            ));
        }
        println!("FVCA_PROMOTION_STABLE_RECOVERY {tx}");
        return Ok(());
    }
    match publish(&confirmed, body.as_bytes()) {
        Err(error)
            if error.kind() == io::ErrorKind::AlreadyExists
                && read_record(&confirmed)? == body.as_bytes() => {}
        result => result?,
    }
    let pending = directory.join(PENDING);
    match read_record(&pending) {
        Ok(contents) if contents == attempt => {
            fs::remove_file(pending)?;
            File::open(directory)?.sync_all()?;
        }
        Ok(_) => (),
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error),
    }
    publish(Path::new(PROMOTED_RELEASE), body.as_bytes())?;
    println!("FVCA_PROMOTED_HYPERVISOR_ACTIVE {tx}");
    Ok(())
}
