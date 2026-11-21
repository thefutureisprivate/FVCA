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
const RETIRE: &str = "retire-channel-image";
const IMAGE: &str = "guest-boot.raw";
const LAUNCH_UNIT: &str = "fvca-activate-guest-trial.service";

#[derive(Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    envelope_sha256: String,
    previous: Active,
    selected: Active,
}

impl Receipt {
    fn name(envelope_sha256: &str) -> String {
        format!("channel-release-{envelope_sha256}.json")
    }

    fn for_trial(store: &Path, trial: &boot::Trial<'_>, packet: &[u8]) -> Result<Option<Self>> {
        let release = store.join(trial.selection.bundle);
        handoff::require_pool_directory(&release)?;
        let hash = digest(packet);
        let Some(bytes) = optional(&release.join(Self::name(&hash)), MANIFEST_BYTES)? else {
            return Ok(None);
        };
        let receipt: Self = serde_json::from_slice(&bytes)?;
        if receipt.envelope_sha256 != hash
            || !receipt
                .previous
                .identifies_guest(trial.stable, trial.stable_epoch)
            || !receipt
                .selected
                .identifies_guest(trial.selection.bundle, trial.candidate_epoch)
            || receipt.selected.sequence <= receipt.previous.sequence
            || receipt.selected.manifest_sha256 == receipt.previous.manifest_sha256
        {
            return Err(invalid("invalid qualified Guest handoff receipt").into());
        }
        Ok(Some(receipt))
    }
}

impl Active {
    fn identifies_guest(&self, bundle: &str, epoch: u64) -> bool {
        self.role == Role::ServiceGuest
            && self.slot.is_none()
            && self.guest_bundle.as_deref() == Some(bundle)
            && self.epoch == epoch
            && self.sequence != 0
            && crate::valid_digest(&self.manifest_sha256)
    }
}

struct Running {
    active: Active,
    fallback: Option<String>,
    approval_sha256: Option<String>,
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

fn current(active: Active, key: &[u8], enrolled_epoch: u64, launch: &str) -> Result<Running> {
    let store = Path::new(boot::STORE);
    let Some(committed) = optional(&store.join(ACTIVE), boot::ENVELOPE_LIMIT as u64)? else {
        if !active.identifies_guest(boot::parse(launch)?.bundle, enrolled_epoch) {
            return Err(
                invalid("recorded Guest bundle or epoch differs from the enrolled boot").into(),
            );
        }
        return Ok(Running {
            active,
            fallback: None,
            approval_sha256: None,
        });
    };
    let running = signed(key, &committed)?;
    if running.candidate_epoch < enrolled_epoch || running.launch != launch {
        return Err(invalid("the active Guest does not match its committed authorization").into());
    }
    let receipt = Receipt::for_trial(store, &running, &committed)?
        .ok_or_else(|| invalid("the committed Guest has no qualified handoff receipt"))?;
    if active != receipt.previous && active != receipt.selected {
        return Err(
            invalid("the committed Guest does not match the qualified channel handoff").into(),
        );
    }
    Ok(Running {
        active: receipt.selected,
        fallback: Some(running.stable.into()),
        approval_sha256: Some(receipt.envelope_sha256),
    })
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
    let running = current(active.clone(), &key, epoch, &launch()?)?;
    if running.active != active {
        save(directory, super::ACTIVE_RELEASE, &running.active)?;
    }
    let store = Path::new(boot::STORE);
    if let Some(packet) = pending(store)?
        && running.approval_sha256.as_ref() == Some(&digest(&packet))
    {
        clear_pending(store, &packet)?;
    }
    retire_obsolete(&running, &key)?;
    Ok(running.active)
}

fn lock_running(active: &Active, key: &[u8]) -> Result<(File, Running)> {
    let lease = handoff::lock_install()?;
    handoff::require_idle()?;
    handoff::require_pool_directory(Path::new(boot::STORE))?;
    let (enrolled_key, enrolled_epoch) = enrolled()?;
    if key != enrolled_key {
        return Err(invalid("Guest trial authority changed during discovery").into());
    }
    let running = current(active.clone(), key, enrolled_epoch, &launch()?)?;
    if running.active != *active {
        return Err(invalid("stable Guest selection changed during discovery").into());
    }
    Ok((lease, running))
}

fn pending(store: &Path) -> Result<Option<Vec<u8>>> {
    optional(&store.join(PENDING), boot::ENVELOPE_LIMIT as u64)
}

fn clear_pending(store: &Path, expected: &[u8]) -> Result<()> {
    if pending(store)?.as_deref() != Some(expected) {
        return Err(invalid("the pending Guest trial changed while it was being retired").into());
    }
    fs::remove_file(store.join(PENDING))?;
    File::open(store)?.sync_all()?;
    Ok(())
}

fn mark_obsolete(
    store: &Path,
    running: &Running,
    old: &boot::Trial<'_>,
    envelope: &[u8],
    authorize: &dyn Fn() -> Result<()>,
) -> Result<()> {
    let bundle = old.selection.bundle;
    if running.active.guest_bundle.as_deref() == Some(bundle)
        || running.fallback.as_deref() == Some(bundle)
    {
        return Ok(());
    }
    let path = store.join(bundle);
    let directory = handoff::require_pool_directory(&path)?;
    if optional(&path.join(RETIRE), boot::ENVELOPE_LIMIT as u64)?.is_none() {
        handoff::publish_record(&directory, RETIRE, envelope, authorize)?;
    }
    Ok(())
}

fn retire_obsolete(running: &Running, key: &[u8]) -> Result<()> {
    let store = Path::new(boot::STORE);
    let pending = pending(store)?;
    let next = pending
        .as_ref()
        .map(|bytes| signed(key, bytes))
        .transpose()?;
    for entry in fs::read_dir(store)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(bundle) = name.to_str().filter(|name| crate::valid_digest(name)) else {
            continue;
        };
        if running.active.guest_bundle.as_deref() == Some(bundle)
            || running.fallback.as_deref() == Some(bundle)
            || next
                .as_ref()
                .is_some_and(|trial| trial.selection.bundle == bundle)
        {
            continue;
        }
        let path = entry.path();
        let directory = handoff::require_pool_directory(&path)?;
        let marker = path.join(RETIRE);
        let Some(envelope) = optional(&marker, boot::ENVELOPE_LIMIT as u64)? else {
            continue;
        };
        let trial = signed(key, &envelope)?;
        if trial.selection.bundle != bundle
            || Receipt::for_trial(store, &trial, &envelope)?.is_none()
        {
            return Err(invalid("invalid retirement record for the superseded Guest image").into());
        }
        let image = path.join(IMAGE);
        if let Some(file) = open_image(&image)? {
            verify_member(
                file,
                &Member {
                    bytes: trial.image_bytes,
                    sha256: trial.image_digest.into(),
                },
            )?;
            fs::remove_file(image)?;
            directory.sync_all()?;
        }
        fs::remove_file(marker)?;
        directory.sync_all()?;
        println!("FVCA_GUEST_IMAGE_RETIRED {bundle}");
    }
    Ok(())
}

fn open_image(path: &Path) -> Result<Option<File>> {
    match private_image(path) {
        Ok(file) => Ok(Some(file)),
        Err(error)
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|e| e.kind() == io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

pub(super) fn withdraw(
    active: &Active,
    sequence: u64,
    key: &[u8],
    authorize: &dyn Fn() -> Result<()>,
) -> Result<()> {
    let (_lease, running) = lock_running(active, key)?;
    let store = Path::new(boot::STORE);
    let Some(envelope) = pending(store)? else {
        return Ok(());
    };
    let trial = signed(key, &envelope)?;
    let Some(receipt) = Receipt::for_trial(store, &trial, &envelope)? else {
        return Ok(());
    };
    if sequence <= receipt.selected.sequence
        || (receipt.previous != *active && receipt.selected != *active)
    {
        return Ok(());
    }
    mark_obsolete(store, &running, &trial, &envelope, authorize)?;
    authorize()?;
    clear_pending(store, &envelope)?;
    println!("FVCA_GUEST_TRIAL_WITHDRAWN {}", trial.transaction);
    retire_obsolete(&running, key)
}

fn clone_image(staged: &Path, candidate: &Path, member: &Member) -> Result<()> {
    let destination = candidate.join(IMAGE);
    if let Some(image) = open_image(&destination)? {
        return verify_member(image, member);
    }
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
    Ok(())
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
    let (_lease, running) = lock_running(active, key)?;
    if active.guest_bundle.as_deref() != Some(trial.stable) {
        return Err(invalid(
            "Guest trial authority or stable bundle differs from the enrolled Guest",
        )
        .into());
    }
    authorize()?;
    let store = Path::new(boot::STORE);
    let inbox = handoff::require_pool_directory(store)?;
    let existing = pending(store)?;
    let displaced = existing
        .as_deref()
        .filter(|bytes| *bytes != envelope)
        .map(|bytes| -> Result<_> {
            let old = signed(key, bytes)?;
            let previous = Receipt::for_trial(store, &old, bytes)?.ok_or_else(|| {
                invalid("an independently staged Guest trial already occupies the inbox")
            })?;
            if previous.selected.sequence >= sequence
                || (previous.previous != *active && previous.selected != *active)
            {
                return Err(invalid(
                    "the pending Guest handoff is outside this channel transition",
                )
                .into());
            }
            Ok((old, bytes))
        })
        .transpose()?;
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
    save(
        &candidate,
        &Receipt::name(&receipt.envelope_sha256),
        &receipt,
    )?;
    inbox.sync_all()?;
    if let Some((old, bytes)) = displaced {
        if old.selection.bundle != trial.selection.bundle {
            mark_obsolete(store, &running, &old, bytes, &authorize)?;
        }
        handoff::replace_record(&inbox, PENDING, envelope, &|| {
            authorize()?;
            if pending(store)?.as_deref() != Some(bytes) {
                return Err(invalid("the pending Guest trial changed during supersession").into());
            }
            Ok(())
        })?;
        println!(
            "FVCA_GUEST_TRIAL_SUPERSEDED {} {}",
            old.transaction, trial.transaction
        );
        retire_obsolete(&running, key)?;
    } else if existing.is_none() {
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
