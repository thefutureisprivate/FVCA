//! Transfer a qualified Service Guest release to the Host-owned direct-boot inbox.

use std::fs::{self, File};
use std::io;
use std::path::Path;

use fvca_trial_authorization::{PENDING, guest as boot};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use super::{Active, digest, save, verify};
use crate::{
    MANIFEST, MANIFEST_BYTES, Manifest, Member, Result, Role, Selection, handoff, invalid, state,
    verify_member,
};

const ACTIVE: &str = "active";
const RECEIPT: &str = "channel-release.json";
const IMAGE: &str = "guest-boot.raw";
const LAUNCH_UNIT: &str = "fvca-activate-guest-trial.service";

#[derive(Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    envelope_sha256: String,
    previous: Active,
    selected: Active,
}

fn signed<'a>(key: &[u8], envelope: &'a [u8]) -> Result<boot::Trial<'a>> {
    let (proof, body) = envelope
        .split_first_chunk::<64>()
        .ok_or_else(|| invalid("truncated Guest trial envelope"))?;
    verify(
        key,
        body,
        proof,
        "invalid independent Guest trial signature",
    )?;
    Ok(boot::Trial::parse(std::str::from_utf8(body)?)?)
}

fn optional(path: &Path, limit: u64) -> Result<Option<Vec<u8>>> {
    match state::read(path, limit) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn private_image(path: &Path) -> Result<File> {
    let file = state::open_regular(path)?;
    let metadata = file.metadata()?;
    use std::os::unix::fs::MetadataExt;
    if metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.nlink() != 1
        || !matches!(metadata.mode() & 0o7777, 0o400 | 0o600)
    {
        return Err(invalid("Guest update image requires a private root-owned file").into());
    }
    Ok(file)
}

fn enrolled() -> Result<([u8; 32], u64)> {
    let enrollment = state::read(
        Path::new(boot::TRIAL_ENROLLMENT),
        boot::ENROLLMENT_LIMIT as u64,
    )?;
    let (key, epoch) = boot::enrollment(&enrollment)?;
    Ok((*key, epoch))
}

fn launch() -> Result<String> {
    Ok(String::from_utf8(state::read(
        Path::new(boot::SELECTION),
        boot::ENVELOPE_LIMIT as u64,
    )?)?)
}

fn current(active: Active, key: &[u8], enrolled_epoch: u64, launch: &str) -> Result<Active> {
    if active.role != Role::ServiceGuest || active.slot.is_some() {
        return Err(invalid("Guest update state does not identify the Service Guest").into());
    }
    let store = Path::new(boot::STORE);
    let Some(committed) = optional(&store.join(ACTIVE), boot::ENVELOPE_LIMIT as u64)? else {
        if active.epoch != enrolled_epoch
            || active.guest_bundle.as_deref() != Some(boot::parse(launch)?.bundle)
        {
            return Err(
                invalid("recorded Guest bundle or epoch differs from the enrolled boot").into(),
            );
        }
        return Ok(active);
    };
    let running = signed(key, &committed)?;
    if running.candidate_epoch < enrolled_epoch || running.launch != launch {
        return Err(invalid("the active Guest does not match its committed authorization").into());
    }
    let release = store.join(running.selection.bundle);
    handoff::require_pool_directory(&release)?;
    let receipt: Receipt =
        serde_json::from_slice(&state::read(&release.join(RECEIPT), MANIFEST_BYTES)?)?;
    if receipt.envelope_sha256 != digest(&committed)
        || receipt.selected.role != Role::ServiceGuest
        || receipt.selected.slot.is_some()
        || receipt.selected.epoch != running.candidate_epoch
        || receipt.selected.guest_bundle.as_deref() != Some(running.selection.bundle)
        || receipt.previous.epoch != running.stable_epoch
        || receipt.previous.guest_bundle.as_deref() != Some(running.stable)
        || receipt.selected.sequence <= receipt.previous.sequence
        || (active != receipt.previous && active != receipt.selected)
    {
        return Err(
            invalid("the committed Guest does not match the qualified channel handoff").into(),
        );
    }
    Ok(receipt.selected)
}

pub(super) fn reconcile(directory: &Path, active: Active, authorized_key: &[u8]) -> Result<Active> {
    let _lease = handoff::lock_install()?;
    handoff::require_idle()?;
    handoff::require_pool_directory(Path::new(boot::STORE))?;
    let (key, epoch) = enrolled()?;
    if key != authorized_key {
        return Err(
            invalid("the signed policy trial authority differs from the enrolled Guest").into(),
        );
    }
    let released = current(active.clone(), &key, epoch, &launch()?)?;
    if released != active {
        save(directory, "active-os-release.json", &released)?;
    }
    Ok(released)
}

fn clone_image(staged: &Path, candidate: &Path, member: &Member) -> Result<()> {
    let destination = candidate.join(IMAGE);
    let image = match private_image(&destination) {
        Ok(image) => image,
        Err(error)
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|e| e.kind() == io::ErrorKind::NotFound) =>
        {
            let input = state::open_regular(&staged.join(IMAGE))?;
            let stage = tempfile::NamedTempFile::new_in(candidate)?;
            fvca_btrfs_boundary::reflink(&input, stage.as_file())?;
            stage.as_file().sync_all()?;
            verify_member(File::open(stage.path())?, member)?;
            rustix::fs::renameat_with(
                rustix::fs::CWD,
                stage.path(),
                rustix::fs::CWD,
                &destination,
                rustix::fs::RenameFlags::NOREPLACE,
            )?;
            File::open(candidate)?.sync_all()?;
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    verify_member(image, member)
}

pub(super) struct Delivery<'a> {
    pub active: &'a Active,
    pub selection: &'a Selection,
    pub sequence: u64,
    pub staged: &'a Path,
    pub envelope: &'a [u8],
    pub key: &'a [u8],
}

pub(super) fn deliver(
    delivery: Delivery<'_>,
    authorize: &dyn Fn() -> Result<()>,
) -> Result<Option<String>> {
    let Delivery {
        active,
        selection,
        sequence,
        staged,
        envelope,
        key,
    } = delivery;
    let trial = signed(key, envelope)?;
    let bytes = state::read(&staged.join(MANIFEST), MANIFEST_BYTES)?;
    let manifest: Manifest = serde_json::from_slice(&bytes)?;
    let members = manifest.members(Role::ServiceGuest, selection.epoch)?;
    let image = members[0].1;
    if trial.candidate_epoch != selection.epoch
        || trial.image_bytes != image.bytes
        || trial.image_digest != image.sha256
        || digest(&bytes) != selection.manifest_sha256
        || trial.stable_epoch != active.epoch
    {
        return Err(
            invalid("Guest trial differs from the exact qualified release transition").into(),
        );
    }
    let receipt = Receipt {
        envelope_sha256: digest(envelope),
        previous: active.clone(),
        selected: Active {
            role: Role::ServiceGuest,
            slot: None,
            guest_bundle: Some(trial.selection.bundle.into()),
            sequence,
            epoch: selection.epoch,
            manifest_sha256: selection.manifest_sha256.clone(),
        },
    };
    let authorize = || {
        authorize()?;
        trial.require_fresh(Timestamp::now().as_second().try_into()?)?;
        Ok(())
    };
    let _lease = handoff::lock_install()?;
    handoff::require_idle()?;
    let (enrolled_key, enrolled_epoch) = enrolled()?;
    let launch = launch()?;
    if key != enrolled_key
        || current(active.clone(), key, enrolled_epoch, &launch)? != *active
        || boot::parse(&launch)?.bundle != trial.stable
    {
        return Err(invalid(
            "Guest trial authority or stable bundle differs from the enrolled Guest",
        )
        .into());
    }
    authorize()?;
    let store = Path::new(boot::STORE);
    let inbox = handoff::require_pool_directory(store)?;
    let existing = optional(&store.join(PENDING), boot::ENVELOPE_LIMIT as u64)?;
    if existing.as_deref().is_some_and(|bytes| bytes != envelope) {
        return Err(invalid("a different Guest trial already occupies the inbox").into());
    }
    let candidate = store.join(trial.selection.bundle);
    state::staged(&candidate)?;
    handoff::require_pool_directory(&candidate)?;
    if candidate
        .join(format!("attempt-{}", boot::ATTEMPT_LIMIT))
        .try_exists()?
    {
        return Ok(None);
    }
    clone_image(staged, &candidate, image)?;
    authorize()?;
    save(&candidate, RECEIPT, &receipt)?;
    inbox.sync_all()?;
    if existing.is_none() {
        handoff::publish_record(&inbox, PENDING, envelope, &authorize)?;
    }
    Ok(Some(trial.transaction.into()))
}

pub(super) fn request_activation() -> Result<()> {
    handoff::request_unit(LAUNCH_UNIT, "Guest")
}

pub(super) fn retire_staging(directory: &Path, retain: Option<&str>) -> Result<()> {
    let staging = directory.join("staged");
    let parent = handoff::require_pool_directory(&staging)?;
    let mut removed = false;
    for entry in fs::read_dir(&staging)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| invalid("invalid Guest staging name"))?;
        if retain == Some(name) {
            continue;
        }
        if !(crate::valid_digest(name) || name.starts_with(".stage-")) {
            return Err(invalid("unrecognized Guest staging directory").into());
        }
        handoff::require_pool_directory(&entry.path())?;
        let files = fs::read_dir(entry.path())?.collect::<io::Result<Vec<_>>>()?;
        for file in &files {
            if !matches!(
                file.file_name().to_str(),
                Some(IMAGE | MANIFEST | crate::QUALIFICATION)
            ) || !file.file_type()?.is_file()
            {
                return Err(invalid("unrecognized Guest staging file").into());
            }
        }
        for file in files {
            fs::remove_file(file.path())?;
        }
        fs::remove_dir(entry.path())?;
        removed = true;
    }
    if removed {
        parent.sync_all()?;
    }
    Ok(())
}
