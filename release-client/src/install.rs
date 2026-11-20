use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use rustix::fs::{self as unix, RenameFlags};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{
    MANIFEST, MANIFEST_BYTES, Manifest, Result, Role, Selection, invalid, state, valid_digest,
    verify_staged,
};

// The installer can see only verified local sources and its private transaction root.
const TRANSFER: &str = "\
[Source]
Type=directory
Path=/staged
PathRelativeTo=explicit
MatchPattern=@v

[Target]
Type=directory
Path=/installed
MatchPattern=@v
InstancesMax=2
";
const BTRFS_SUPER_MAGIC: u64 = 0x9123_683e;

#[derive(Clone, Copy)]
pub enum Operation<'a> {
    Initialize(&'a Path),
    Prepare { slots: &'a Path, active: &'a Path },
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Slot {
    A,
    B,
}

impl Slot {
    fn name(self) -> &'static str {
        match self {
            Self::A => "slot-a",
            Self::B => "slot-b",
        }
    }

    fn other(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Active {
    slot: Slot,
    epoch: u64,
    manifest_sha256: String,
}

struct Identity {
    epoch: u64,
    manifest_sha256: String,
}

fn manifest(directory: &Path) -> Result<(Vec<u8>, Manifest, Identity)> {
    state::directory(directory)?;
    let bytes = state::read(&directory.join(MANIFEST), MANIFEST_BYTES)?;
    let release: Manifest = serde_json::from_slice(&bytes)?;
    let identity = Identity {
        epoch: release.epoch,
        manifest_sha256: hex::encode(Sha256::digest(&bytes)),
    };
    Ok((bytes, release, identity))
}

fn verify(directory: &Path, role: Role, epoch: u64, digest: &str) -> Result<()> {
    let (bytes, release, identity) = manifest(directory)?;
    if identity.epoch != epoch || identity.manifest_sha256 != digest {
        return Err(invalid("installed release does not match the approved slot identity").into());
    }
    verify_staged(directory, &bytes, &release.members(role, epoch)?)
}

fn existing(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            state::directory(path)?;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn select_slot(operation: Operation<'_>, store: &Path, selected: &Selection) -> Result<Slot> {
    match operation {
        Operation::Initialize(_) => {
            if existing(&store.join(Slot::B.name()))? {
                return Err(invalid("initialization requires an empty A/B slot store").into());
            }
            Ok(Slot::A)
        }
        Operation::Prepare { active, .. } => {
            let active: Active = serde_json::from_slice(&state::read(active, MANIFEST_BYTES)?)?;
            if !valid_digest(&active.manifest_sha256) || active.epoch < selected.minimum_epoch {
                return Err(invalid("active slot is outside the approved recovery epoch").into());
            }
            if selected.epoch <= active.epoch {
                return Err(invalid("inactive release must advance the active epoch").into());
            }
            verify(
                &store.join(active.slot.name()),
                selected.role,
                active.epoch,
                &active.manifest_sha256,
            )?;
            Ok(active.slot.other())
        }
    }
}

fn transfer(work: &Path, incoming: &Path, digest: &str) -> Result<PathBuf> {
    let definitions = work.join("etc/sysupdate.d");
    fs::create_dir_all(&definitions)?;
    fs::write(definitions.join("10-fvca.transfer"), TRANSFER)?;
    let target = work.join("installed");
    state::staged(&target)?;
    let status = Command::new("/usr/lib/systemd/systemd-sysupdate")
        .env_clear()
        .arg("--no-pager")
        .arg("--sync=yes")
        .arg("--cleanup=no")
        .arg("--root")
        .arg(work)
        .arg("--transfer-source")
        .arg(incoming)
        .args(["update", digest])
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!("systemd-sysupdate exited with {status}")).into());
    }
    Ok(target.join(digest))
}

pub fn execute(operation: Operation<'_>, selected: &Selection, incoming: &Path) -> Result<()> {
    let store = match &operation {
        Operation::Initialize(store) | Operation::Prepare { slots: store, .. } => store,
    };
    let _lock = state::lock(store)?;
    let store = store.canonicalize()?;
    let directory = File::open(&store)?;
    if unix::fstatfs(&directory)?.f_type as u64 != BTRFS_SUPER_MAGIC {
        return Err(invalid("release slots require a Btrfs filesystem").into());
    }

    let slot = select_slot(operation, &store, selected)?;
    let destination = store.join(slot.name());
    let replace = existing(&destination)?;
    if replace {
        let (bytes, release, identity) = manifest(&destination)?;
        verify_staged(
            &destination,
            &bytes,
            &release.members(selected.role, identity.epoch)?,
        )?;
        if identity.manifest_sha256 == selected.manifest_sha256 && identity.epoch == selected.epoch
        {
            directory.sync_all()?;
            println!(
                "FVCA_SLOT_PREPARED {} {} {}",
                slot.name(),
                selected.epoch,
                destination.display()
            );
            return Ok(());
        }
        if matches!(operation, Operation::Initialize(_)) {
            return Err(invalid(
                "initialization requires an empty A/B slot store or the matching initial tuple",
            )
            .into());
        }
    }

    let work = tempfile::Builder::new()
        .prefix(".prepare-")
        .tempdir_in(&store)?;
    let incoming = incoming.canonicalize()?;
    let installed = transfer(work.path(), &incoming, &selected.manifest_sha256)?;
    verify(
        &installed,
        selected.role,
        selected.epoch,
        &selected.manifest_sha256,
    )?;
    for entry in fs::read_dir(&installed)? {
        state::open_regular(&entry?.path())?.sync_all()?;
    }
    File::open(&installed)?.sync_all()?;
    let flags = if replace {
        RenameFlags::EXCHANGE
    } else {
        RenameFlags::NOREPLACE
    };
    unix::renameat_with(unix::CWD, &installed, unix::CWD, &destination, flags)?;
    File::open(work.path().join("installed"))?.sync_all()?;
    directory.sync_all()?;
    work.close()?;
    println!(
        "FVCA_SLOT_PREPARED {} {} {}",
        slot.name(),
        selected.epoch,
        destination.display()
    );
    Ok(())
}
