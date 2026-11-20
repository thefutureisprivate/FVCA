//! Deliver an already authorized approval to the authenticated Host data mount.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;

use fvca_trial_authorization::{APPROVAL_LIMIT, PENDING};
use rustix::fs::{self, AtFlags, CWD, Mode, OFlags, StatxFlags};
use rustix::io::Errno;

use crate::{Result, install::BTRFS_SUPER_MAGIC, invalid};

const HOST_DATA: &str = "/run/fvca/host-data";
const DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

fn mount_id(file: &File) -> Result<u64> {
    let stat = fs::statx(file, "", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID)?;
    if stat.stx_mask & StatxFlags::MNT_ID.bits() == 0 {
        return Err(invalid("could not identify the Host data mount").into());
    }
    Ok(stat.stx_mnt_id)
}

fn private_directory(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if metadata.uid() != 0 || metadata.gid() != 0 || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err(invalid(
            "Host trial inbox must be a private root-owned directory",
        ));
    }
    Ok(())
}

pub fn publish(envelope: &[u8], authorize: &dyn Fn() -> Result<()>) -> Result<()> {
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
        return Err(invalid("trial handoff requires the mounted Btrfs Host data pool").into());
    }
    private_directory(&host)?;
    match fs::mkdirat(&host, "boot-trials", Mode::RUSR | Mode::WUSR | Mode::XUSR) {
        Ok(()) => host.sync_all()?,
        Err(Errno::EXIST) => (),
        Err(error) => return Err(error.into()),
    }
    let inbox = File::from(fs::openat(&host, "boot-trials", DIRECTORY, Mode::empty())?);
    private_directory(&inbox)?;
    if mount_id(&inbox)? != id {
        return Err(invalid("trial inbox is outside the mounted Host data pool").into());
    }
    let flags =
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
    match fs::openat(&inbox, PENDING, flags, Mode::empty()) {
        Ok(existing) => {
            let existing = File::from(existing);
            let meta = existing.metadata()?;
            if !meta.is_file()
                || meta.uid() != 0
                || meta.gid() != 0
                || meta.nlink() != 1
                || meta.permissions().mode() & 0o7777 != 0o600
            {
                return Err(invalid("pending trial is not a private root-owned file").into());
            }
            let mut bytes = Vec::new();
            (&existing)
                .take((APPROVAL_LIMIT + 1) as u64)
                .read_to_end(&mut bytes)?;
            if bytes != envelope {
                return Err(invalid("another trial already occupies the Host inbox").into());
            }
            authorize()?;
            existing.sync_all()?;
            inbox.sync_all()?;
            return Ok(());
        }
        Err(Errno::NOENT) => (),
        Err(error) => return Err(error.into()),
    }

    let pinned = PathBuf::from(format!("/proc/self/fd/{}", inbox.as_raw_fd()));
    let mut record = tempfile::NamedTempFile::new_in(&pinned)?;
    record.write_all(envelope)?;
    record.as_file().sync_all()?;
    authorize()?;
    fs::renameat_with(
        CWD,
        record.path(),
        &inbox,
        PENDING,
        fs::RenameFlags::NOREPLACE,
    )?;
    inbox.sync_all()?;
    Ok(())
}
