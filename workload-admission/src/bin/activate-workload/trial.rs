//! Switch only the affected workload and commit its selection after local health.

use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::Command;

use fvca_workload_admission::{authorization_identity, channel, read_bounded};
use rustix::fs::{CWD, RenameFlags, renameat_with};

use super::{
    Result, SERVICE, SYSTEMCTL, TRUST, check_workload_unit, mount_verified, read_trust,
    require_guest_data, run as checked_run, stage, start_workload, stop_workload, unmount_workload,
};

pub(super) fn recover() -> Result<()> {
    let store = Path::new(stage::STORE);
    if !stage::directory_present(&store.join(stage::TRIAL))? {
        return Ok(());
    }
    let data = require_guest_data("rw,nodev,nosuid,noexec")?;
    stage::pool_directory(store, data.dev())?;
    let trust = read_trust(data.dev())?;
    let selected = stage::selected_bundle(store)?;
    let mounted = stage::mounted_authorization()?.unwrap_or_default();
    let identity = authorization_identity(&selected, &trust);

    // A verified, unchanged running instance may outlive its deployment permit.
    // Starting it again always requires full fresh admission.
    let already_running = identity.as_ref().is_ok_and(|digest| digest == &mounted)
        && check_workload_unit().is_ok()
        && checked_run(Command::new(SYSTEMCTL).args(["is-active", "--quiet", SERVICE])).is_ok();
    if !already_running {
        let stable = stage::verify_selection(store, &trust, data.dev());
        stop_workload()?;
        unmount_workload()?;
        mount_verified(&stable?)?;
        start_workload(true)?;
    }
    stage::discard_trial(store, data.dev())?;
    println!("FVCA_WORKLOAD_TRIAL_RECOVERED");
    Ok(())
}

pub(super) fn run() -> Result<()> {
    let store = Path::new(stage::STORE);
    let staged = store.join(stage::STAGED);
    let trial = store.join(stage::TRIAL);
    if stage::directory_present(&trial)? {
        return recover();
    }
    if !stage::directory_present(&staged)? {
        return Ok(());
    }
    let data = require_guest_data("rw,nodev,nosuid,noexec")?;
    let directory = stage::pool_directory(store, data.dev())?;
    let mounted = stage::mounted_authorization()?
        .ok_or_else(|| io::Error::other("the committed workload is not mounted"))?;
    check_workload_unit()?;
    checked_run(Command::new(SYSTEMCTL).args(["is-active", "--quiet", SERVICE]))?;
    let trust = read_trust(data.dev())?;
    let transition = stage::verify_staged(store, &staged, &mounted, &trust, data.dev())?;
    let channel_permit = if Path::new(TRUST).join(channel::POLICY).try_exists()? {
        let ready: channel::Permit =
            serde_json::from_slice(&read_bounded(Path::new(channel::READY), 4096)?)?;
        ready.authorize(&transition)?;
        Some(ready)
    } else {
        None
    };
    let repeated = stage::attempted(store, data.dev())?.as_deref()
        == Some(transition.approval_digest.as_str());

    // Persist an unfinished trial before touching the running workload.
    renameat_with(CWD, &staged, CWD, &trial, RenameFlags::NOREPLACE)?;
    directory.sync_all()?;
    if repeated {
        stage::discard_trial(store, data.dev())?;
        return Err(
            io::Error::other("the last signed workload grant has already been tried").into(),
        );
    }
    stage::record_attempt(store, &directory, &transition.approval_digest)?;
    transition.require_fresh()?;
    transition.require_unrevoked(&trust)?;
    if let Some(permit) = &channel_permit {
        permit.require_fresh()?;
    }
    println!(
        "FVCA_WORKLOAD_TRIAL_STARTED {} {} {}",
        transition.approval_digest,
        transition.current.authorization_digest(),
        transition.candidate.authorization_digest(),
    );
    stop_workload()?;
    unmount_workload()?;
    mount_verified(&transition.candidate)?;
    println!("FVCA_WORKLOAD_TRIAL_MOUNTED {}", transition.approval_digest);
    start_workload(true)?;
    transition.require_fresh()?;
    transition.require_unrevoked(&trust)?;
    if let Some(permit) = &channel_permit {
        permit.require_fresh()?;
    }

    // The selected name is the only boot authority. A power cut before this
    // step leaves the old executable selected. Both outcomes keep all data.
    let selected = store.join(stage::SELECTED);
    if stage::directory_present(&selected)? {
        renameat_with(CWD, &trial, CWD, selected, RenameFlags::EXCHANGE)?;
    } else {
        renameat_with(CWD, &trial, CWD, selected, RenameFlags::NOREPLACE)?;
    }
    directory.sync_all()?;
    println!(
        "FVCA_WORKLOAD_TRIAL_COMMITTED {} {}",
        transition.approval_digest,
        transition.candidate.authorization_digest(),
    );
    if stage::directory_present(&trial)? {
        stage::discard_trial(store, data.dev())?;
    }
    Ok(())
}
