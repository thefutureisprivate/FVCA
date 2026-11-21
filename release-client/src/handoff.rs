//! Deliver an already authorized approval to the authenticated Host data mount.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use fvca_trial_authorization::{
    APPROVAL_LIMIT, GUEST_CAPTURE_LOCK, PENDING, WITHDRAWN_SUFFIX, guest, guest_config,
};
use rustix::fs::{self, AtFlags, CWD, Mode, OFlags, StatxFlags};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};

use crate::{Member, Result, channel::digest, install::BTRFS_SUPER_MAGIC, invalid, state};

const HOST_DATA: &str = "/run/fvca/host-data";
const ACTIVATE_TRIAL: &str = "fvca-activate-hypervisor-trial.service";
const ACTIVATION: &str = "/run/fvca/hypervisor-activation";
const BOOT_NEXT: &str = "/sys/firmware/efi/efivars/BootNext-8be4df61-93ca-11d2-aa0d-00e098032b8c";
const CHANNEL_ORIGIN: &str = "user.fvca.channel-origin";
const DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

#[derive(Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ChannelOrigin {
    pub channel: String,
    pub sequence: u64,
    pub stable_manifest: String,
    pub candidate_manifest: String,
    pub trial: Member,
}

pub(super) struct ChannelPending {
    inbox: File,
    file: File,
    pub origin: ChannelOrigin,
    pub envelope: Vec<u8>,
}

impl ChannelPending {
    fn read(inbox: File) -> Result<Option<Self>> {
        let Some(file) = open_record(&inbox, PENDING)? else {
            return Ok(None);
        };
        let mut attribute = [0; 512];
        let bytes = match fs::fgetxattr(&file, CHANNEL_ORIGIN, &mut attribute[..]) {
            Ok(bytes) => bytes,
            Err(Errno::NODATA) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let origin: ChannelOrigin = serde_json::from_slice(&attribute[..bytes])?;
        let envelope = read_approval(&file)?;
        if origin.trial.bytes != envelope.len() as u64 || origin.trial.sha256 != digest(&envelope) {
            return Err(invalid(
                "pending Hypervisor approval differs from its channel delivery",
            )
            .into());
        }
        Ok(Some(Self {
            inbox,
            file,
            origin,
            envelope,
        }))
    }

    pub fn withdraw(self, transaction: &str, authorize: &dyn Fn() -> Result<()>) -> Result<bool> {
        // Preserve a trial already reserved by initramfs, including its health
        // and promotion path on return to the stable slot.
        if exists(&self.inbox, transaction)? {
            return Ok(false);
        }
        let current = Self::read(self.inbox.try_clone()?)?
            .ok_or_else(|| invalid("pending Hypervisor approval disappeared before withdrawal"))?;
        if current.file.metadata()?.ino() != self.file.metadata()?.ino()
            || current.origin != self.origin
            || current.envelope != self.envelope
        {
            return Err(invalid("pending Hypervisor approval changed before withdrawal").into());
        }
        let withdrawn = format!("{transaction}{WITHDRAWN_SUFFIX}");
        authorize()?;
        fs::renameat_with(
            &self.inbox,
            PENDING,
            &self.inbox,
            withdrawn,
            fs::RenameFlags::NOREPLACE,
        )?;
        self.inbox.sync_all()?;
        Ok(true)
    }
}

pub(super) fn channel_pending() -> Result<Option<ChannelPending>> {
    let (host, id) = host_data()?;
    match inbox(&host, id)? {
        Some(inbox) => ChannelPending::read(inbox),
        None => Ok(None),
    }
}

pub(crate) fn mount_id(file: &File) -> io::Result<u64> {
    let stat = fs::statx(file, "", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID)?;
    if stat.stx_mask & StatxFlags::MNT_ID.bits() == 0 {
        return Err(invalid("could not identify the Host data mount"));
    }
    Ok(stat.stx_mnt_id)
}

pub(crate) fn open_child(
    parent: &File,
    name: impl AsRef<OsStr>,
    flags: OFlags,
) -> io::Result<File> {
    let name = name.as_ref();
    if name.is_empty() || name == "." || name == ".." || name.as_encoded_bytes().contains(&b'/') {
        return Err(invalid("expected one relative path component"));
    }
    let file = File::from(fs::openat(
        parent,
        name,
        flags | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?);
    if mount_id(&file)? != mount_id(parent)? {
        return Err(invalid("entry is outside the selected mount"));
    }
    Ok(file)
}

fn private_directory(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if metadata.uid() != 0 || metadata.gid() != 0 || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err(invalid(
            "Host data paths require private root-owned directories",
        ));
    }
    Ok(())
}

pub(crate) fn host_data() -> Result<(File, u64)> {
    let host = File::from(fs::open(HOST_DATA, DIRECTORY, Mode::empty())?);
    let parent = fs::statx(
        CWD,
        "/run/fvca",
        AtFlags::SYMLINK_NOFOLLOW,
        StatxFlags::MNT_ID,
    )?;
    let id = mount_id(&host)?;
    if parent.stx_mask & StatxFlags::MNT_ID.bits() == 0
        || id == parent.stx_mnt_id
        || fs::fstatfs(&host)?.f_type as u64 != BTRFS_SUPER_MAGIC
    {
        return Err(invalid("this operation requires the mounted Btrfs Host data pool").into());
    }
    private_directory(&host)?;
    Ok((host, id))
}

pub fn require_pool_directory(path: &Path) -> Result<File> {
    let (mut state, _) = host_data()?;
    let relative = path.strip_prefix(HOST_DATA)?;
    if relative.as_os_str().is_empty() {
        return Err(invalid("expected a directory within the Host pool").into());
    }
    for entry in relative.components() {
        let Component::Normal(name) = entry else {
            return Err(invalid("invalid Host pool directory component").into());
        };
        state = open_child(&state, name, DIRECTORY)?;
    }
    private_directory(&state)?;
    Ok(state)
}

pub fn lock_install() -> Result<File> {
    let lock = install_lease()?;
    lock.try_lock().map_err(io::Error::from)?;
    Ok(lock)
}

pub(crate) fn install_lease() -> Result<File> {
    let lock = state::open_regular(Path::new(GUEST_CAPTURE_LOCK))?;
    private_file(&lock)?;
    Ok(lock)
}

pub fn private_file(file: &File) -> io::Result<()> {
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.gid() != 0
        || meta.nlink() != 1
        || meta.permissions().mode() & 0o7777 != 0o600
    {
        return Err(invalid("Host handoff requires a private root-owned file"));
    }
    Ok(())
}

fn inbox(host: &File, id: u64) -> Result<Option<File>> {
    let inbox = match fs::openat(host, "boot-trials", DIRECTORY, Mode::empty()) {
        Ok(fd) => File::from(fd),
        Err(Errno::NOENT) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    private_directory(&inbox)?;
    if mount_id(&inbox)? != id {
        return Err(invalid("trial inbox is outside the mounted Host data pool").into());
    }
    Ok(Some(inbox))
}

fn open_record(inbox: &File, name: &str) -> Result<Option<File>> {
    let flags =
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
    match fs::openat(inbox, name, flags, Mode::empty()) {
        Ok(existing) => {
            let existing = File::from(existing);
            private_file(&existing)?;
            Ok(Some(existing))
        }
        Err(Errno::NOENT) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn read_approval(file: &File) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take((APPROVAL_LIMIT + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > APPROVAL_LIMIT {
        return Err(invalid("Hypervisor approval exceeds its size bound"));
    }
    Ok(bytes)
}

fn matching_record(inbox: &File, name: &str, envelope: &[u8]) -> Result<Option<File>> {
    let Some(existing) = open_record(inbox, name)? else {
        return Ok(None);
    };
    if read_approval(&existing)? != envelope {
        return Err(invalid(if name == PENDING {
            "another trial already occupies the Host inbox"
        } else {
            "a different signed approval already occupies the Host inbox"
        })
        .into());
    }
    Ok(Some(existing))
}

fn exists(inbox: &File, name: &str) -> Result<bool> {
    match fs::statat(inbox, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(Errno::NOENT) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn require_not_withdrawn(inbox: &File, transaction: &str) -> Result<()> {
    if exists(inbox, &format!("{transaction}{WITHDRAWN_SUFFIX}"))? {
        return Err(invalid("the signed Hypervisor trial has been withdrawn").into());
    }
    Ok(())
}

pub fn check_install(transaction: &str, envelope: &[u8]) -> Result<bool> {
    require_idle()?;
    let (host, id) = host_data()?;
    let Some(inbox) = inbox(&host, id)? else {
        return Ok(false);
    };
    require_not_withdrawn(&inbox, transaction)?;
    if exists(&inbox, transaction)? {
        return Err(invalid("the signed trial transaction has already been consumed").into());
    }
    Ok(matching_record(&inbox, PENDING, envelope)?.is_some())
}

pub fn require_idle() -> Result<()> {
    fvca_trial_authorization::firmware::require_idle()?;
    for path in [
        PathBuf::from(ACTIVATION),
        PathBuf::from(BOOT_NEXT),
        PathBuf::from("/run/fvca/boot-trial-started"),
        Path::new("/run/fvca").join(guest::FENCE),
    ] {
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                return Err(
                    invalid("a reboot or release trial activation is already pending").into(),
                );
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

pub fn publish(
    envelope: &[u8],
    transaction: &str,
    promotion: Option<&[u8]>,
    configuration: Option<&[u8]>,
    origin: Option<&ChannelOrigin>,
    authorize: &dyn Fn() -> Result<()>,
) -> Result<()> {
    let (host, id) = host_data()?;
    match fs::mkdirat(&host, "boot-trials", Mode::RUSR | Mode::WUSR | Mode::XUSR) {
        Ok(()) => host.sync_all()?,
        Err(Errno::EXIST) => (),
        Err(error) => return Err(error.into()),
    }
    let inbox = inbox(&host, id)?.ok_or_else(|| invalid("trial inbox disappeared"))?;
    require_not_withdrawn(&inbox, transaction)?;
    let pending = matching_record(&inbox, PENDING, envelope)?;
    for (suffix, packet) in [
        (".standing-promotion", promotion),
        (guest_config::CHANGE_SUFFIX, configuration),
    ] {
        let name = format!("{transaction}{suffix}");
        if let Some(packet) = packet {
            match matching_record(&inbox, &name, packet)? {
                Some(existing) => existing.sync_all()?,
                None if pending.is_none() || configuration.is_none() => {
                    publish_record(&inbox, &name, packet, authorize)?
                }
                None => {
                    return Err(
                        invalid("published trial lacks its original signed approvals").into(),
                    );
                }
            }
        } else if suffix == guest_config::CHANGE_SUFFIX {
            match fs::statat(&inbox, &name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(_) => {
                    return Err(invalid(
                        "trial already has a signed approval for this transaction",
                    )
                    .into());
                }
                Err(Errno::NOENT) => (),
                Err(error) => return Err(error.into()),
            }
        }
    }
    if let Some(existing) = pending {
        authorize()?;
        existing.sync_all()?;
        inbox.sync_all()?;
        return Ok(());
    }

    inbox.sync_all()?;
    write_record(
        &inbox,
        PENDING,
        envelope,
        fs::RenameFlags::NOREPLACE,
        origin,
        authorize,
    )
}

pub fn publish_record(
    inbox: &File,
    name: &str,
    envelope: &[u8],
    authorize: &dyn Fn() -> Result<()>,
) -> Result<()> {
    write_record(inbox, name, envelope, fs::RenameFlags::NOREPLACE, None, authorize)
}

pub fn replace_record(
    inbox: &File,
    name: &str,
    envelope: &[u8],
    authorize: &dyn Fn() -> Result<()>,
) -> Result<()> {
    write_record(inbox, name, envelope, fs::RenameFlags::empty(), None, authorize)
}

fn write_record(
    inbox: &File,
    name: &str,
    envelope: &[u8],
    flags: fs::RenameFlags,
    origin: Option<&ChannelOrigin>,
    authorize: &dyn Fn() -> Result<()>,
) -> Result<()> {
    let pinned = PathBuf::from(format!("/proc/self/fd/{}", inbox.as_raw_fd()));
    let mut record = tempfile::NamedTempFile::new_in(&pinned)?;
    record.write_all(envelope)?;
    // Publish the envelope and its provenance together on the same inode.
    if let Some(origin) = origin {
        let origin = serde_json::to_vec(origin)?;
        fs::fsetxattr(record.as_file(), CHANNEL_ORIGIN, &origin, fs::XattrFlags::CREATE)?;
    }
    record.as_file().sync_all()?;
    authorize()?;
    fs::renameat_with(CWD, record.path(), inbox, name, flags)?;
    inbox.sync_all()?;
    Ok(())
}

pub fn request_activation() -> Result<()> {
    request_unit(ACTIVATE_TRIAL, "Hypervisor")
}

pub fn request_unit(unit: &str, release: &str) -> Result<()> {
    let status = Command::new("/usr/bin/systemctl")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .args([
            "--no-ask-password",
            "--no-block",
            "--job-mode=fail",
            "start",
            unit,
        ])
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "systemd declined the {release} activation job ({status})"
        ))
        .into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires root and a temporary directory with user xattr support"]
    fn withdraws_only_the_intact_channel_delivery_and_rejects_replay() -> Result<()> {
        let work = tempfile::tempdir()?;
        let inbox = File::open(work.path())?;
        let transaction = "03dfd36b-82ab-44f1-bc27-d8230a3ebd3c";
        let withdrawn = work.path().join(format!("{transaction}{WITHDRAWN_SUFFIX}"));
        let authorized = || Ok(());
        let denied = || Err(invalid("expired authorization").into());
        let envelope = b"exact channel trial approval";
        let origin = ChannelOrigin {
            channel: "stable".into(),
            sequence: 2,
            stable_manifest: "a".repeat(64),
            candidate_manifest: "b".repeat(64),
            trial: Member {
                bytes: envelope.len() as u64,
                sha256: digest(envelope),
            },
        };
        let publish_channel = || {
            write_record(
                &inbox,
                PENDING,
                envelope,
                fs::RenameFlags::NOREPLACE,
                Some(&origin),
                &authorized,
            )
        };
        let pending = || -> Result<ChannelPending> {
            ChannelPending::read(inbox.try_clone()?)?
                .ok_or_else(|| invalid("expected the channel delivery").into())
        };
        let inbox_path = work.path().join(PENDING);

        publish_record(&inbox, PENDING, envelope, &authorized)?;
        assert!(ChannelPending::read(inbox.try_clone()?)?.is_none());
        std::fs::remove_file(&inbox_path)?;

        publish_channel()?;
        let reserved = work.path().join(transaction);
        std::fs::write(&reserved, envelope)?;
        assert!(!pending()?.withdraw(transaction, &authorized)?);
        std::fs::remove_file(reserved)?;
        assert!(pending()?.withdraw(transaction, &denied).is_err());
        assert!(!withdrawn.try_exists()?);

        let original = pending()?;
        std::fs::remove_file(&inbox_path)?;
        publish_record(&inbox, PENDING, envelope, &authorized)?;
        assert!(original.withdraw(transaction, &authorized).is_err());
        assert_eq!(std::fs::read(&inbox_path)?, envelope);
        std::fs::remove_file(&inbox_path)?;

        publish_channel()?;
        std::fs::write(&inbox_path, b"different trial approval")?;
        assert!(ChannelPending::read(inbox.try_clone()?).is_err());
        std::fs::remove_file(&inbox_path)?;
        publish_channel()?;

        assert!(pending()?.withdraw(transaction, &authorized)?);
        assert_eq!(std::fs::read(&withdrawn)?, envelope);
        assert!(!inbox_path.try_exists()?);
        assert!(require_not_withdrawn(&inbox, transaction).is_err());
        assert!(ChannelPending::read(inbox.try_clone()?)?.is_none());
        Ok(())
    }

    #[test]
    fn child_open_stays_on_the_parent_mount() -> Result<()> {
        let work = tempfile::tempdir()?;
        let root = File::open(work.path())?;
        std::fs::write(work.path().join("record"), b"receipt")?;
        std::os::unix::fs::symlink("record", work.path().join("alias"))?;
        let mut body = String::new();
        open_child(&root, "record", OFlags::RDONLY)?.read_to_string(&mut body)?;
        assert_eq!(body, "receipt");
        for invalid in ["", ".", "..", "alias", "record/child", "/etc/passwd"] {
            assert!(
                open_child(&root, invalid, OFlags::RDONLY).is_err(),
                "{invalid}"
            );
        }
        let err = open_child(&File::open("/")?, "proc", DIRECTORY).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        Ok(())
    }
}
