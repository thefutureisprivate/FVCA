//! Retire the scheduled Host's downloaded tuples after authenticating the channel head.

use std::fs::{self, File};
use std::io;
use std::path::Path;

use rustix::fs::{AtFlags, Dir, Mode, OFlags, RenameFlags, XattrFlags};
use rustix::io::Errno;

use super::{Active, Role, save};
use crate::{MANIFEST, MANIFEST_BYTES, QUALIFICATION, Result, handoff, invalid, state, valid_digest};

const ORIGIN: &str = "user.fvca.host-download";
const RECOVERY: &str = "recovery-os-release.json";
const INCOMPLETE: &str = ".stage-";
const RETIRED: &str = ".retired-";
const DIRECTORY: OFlags = OFlags::RDONLY.union(OFlags::DIRECTORY);
const MEMBER: OFlags = OFlags::RDONLY.union(OFlags::NONBLOCK).union(OFlags::NOCTTY);

pub(super) fn record_recovery(directory: &Path, prior: &Active) -> Result<()> {
    if recovery(directory)?.as_ref() != Some(prior) {
        save(directory, RECOVERY, prior)?;
    }
    Ok(())
}

fn recovery(directory: &Path) -> Result<Option<Active>> {
    let bytes = match state::read(&directory.join(RECOVERY), MANIFEST_BYTES) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let record: Active = serde_json::from_slice(&bytes)?;
    if record.role != Role::Hypervisor
        || record.slot.is_none()
        || record.guest_bundle.is_some()
        || record.sequence == 0
        || record.epoch == 0
        || !valid_digest(&record.manifest_sha256)
    {
        return Err(invalid("invalid Hypervisor recovery cache pin").into());
    }
    Ok(Some(record))
}

pub(crate) fn mark(directory: &File, digest: &str) -> Result<()> {
    rustix::fs::fsetxattr(directory, ORIGIN, digest.as_bytes(), XattrFlags::CREATE)?;
    directory.sync_all()?;
    Ok(())
}

pub(crate) fn preserve(path: &Path) -> Result<()> {
    let directory = File::from(rustix::fs::open(
        path,
        DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    match rustix::fs::fremovexattr(&directory, ORIGIN) {
        Ok(()) => directory.sync_all()?,
        Err(Errno::NODATA | Errno::NOTSUP) => (),
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn origin(directory: &File) -> Result<Option<String>> {
    let mut bytes = [0; 64];
    let length = match rustix::fs::fgetxattr(directory, ORIGIN, &mut bytes[..]) {
        Ok(length) => length,
        Err(Errno::NODATA) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let digest = std::str::from_utf8(&bytes[..length])?;
    if !valid_digest(digest) {
        return Err(invalid("invalid scheduled Host cache origin").into());
    }
    Ok(Some(digest.into()))
}

fn members(directory: &File) -> Result<Vec<String>> {
    let mut files = Vec::new();
    for entry in Dir::read_from(directory)? {
        let entry = entry?;
        let name = entry.file_name().to_str()?;
        if matches!(name, "." | "..") {
            continue;
        }
        if !matches!(
            name,
            MANIFEST | QUALIFICATION | "boot.raw" | "vm-runtime.raw" | "guest-boot.raw"
        ) {
            return Err(invalid("unexpected entry in the scheduled Host cache").into());
        }
        handoff::private_file_with_mode(&handoff::open_child(directory, name, MEMBER)?, 0o400)?;
        files.push(name.into());
    }
    Ok(files)
}

pub(super) fn retire(
    directory: &Path,
    active: &Active,
    selected: Option<&str>,
    authorize: &dyn Fn() -> Result<()>,
) -> Result<()> {
    let staging = directory.join("staged");
    match fs::symlink_metadata(&staging) {
        Ok(_) => (),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    let parent = handoff::require_pool_directory(&staging)?;
    let recovery = recovery(directory)?;
    let mut lease = None;
    let mut entries = Dir::read_from(&parent)?
        .map(|entry| Ok(entry?.file_name().to_str()?.to_owned()))
        .collect::<Result<Vec<_>>>()?;
    // Finish any already-detached tuple before processing a newly staged copy
    // of the same digest. The detached name sorts ahead of the digest.
    entries.sort_unstable();
    for name in &entries {
        let name = name.as_str();
        let retained = name == active.manifest_sha256
            || recovery.as_ref().is_some_and(|record| name == record.manifest_sha256)
            || selected == Some(name);
        let incomplete = name.starts_with(INCOMPLETE);
        let retired = name.strip_prefix(RETIRED).filter(|digest| valid_digest(digest));
        if retained || !(valid_digest(name) || incomplete || retired.is_some()) {
            continue;
        }
        let candidate = handoff::open_child(&parent, name, DIRECTORY)?;
        let Some(digest) = origin(&candidate)? else {
            continue;
        };
        handoff::private_directory(&candidate)?;
        if !incomplete && retired.unwrap_or(name) != digest {
            return Err(invalid("scheduled Host cache origin differs from its directory name").into());
        }
        if lease.is_none() {
            let acquired = handoff::lock_install()?;
            if handoff::trial_queued()? {
                return Ok(());
            }
            handoff::require_idle()?;
            lease = Some(acquired);
        }
        let files = members(&candidate)?;
        authorize()?;
        let detached;
        let name = if !incomplete && retired.is_none() {
            // A replacement offer may arrive after an interrupted removal.
            // Detach the tuple before unlinking any of its verified members.
            detached = format!("{RETIRED}{digest}");
            rustix::fs::renameat_with(&parent, name, &parent, &detached, RenameFlags::NOREPLACE)?;
            parent.sync_all()?;
            detached.as_str()
        } else {
            name
        };
        for file in files {
            rustix::fs::unlinkat(&candidate, file, AtFlags::empty())?;
        }
        rustix::fs::unlinkat(&parent, name, AtFlags::REMOVEDIR)?;
        parent.sync_all()?;
        println!("FVCA_HYPERVISOR_STAGE_RETIRED {digest}");
    }
    Ok(())
}
