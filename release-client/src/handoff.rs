//! Deliver an already authorized approval to the authenticated Host data mount.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use fvca_trial_authorization::{APPROVAL_LIMIT, GUEST_CAPTURE_LOCK, PENDING, guest, guest_config};
use rustix::fs::{self, AtFlags, CWD, Mode, OFlags, StatxFlags};
use rustix::io::Errno;

use crate::{Result, install::BTRFS_SUPER_MAGIC, invalid, state};

const HOST_DATA: &str = "/run/fvca/host-data";
const ACTIVATE_TRIAL: &str = "fvca-activate-hypervisor-trial.service";
const ACTIVATION: &str = "/run/fvca/hypervisor-activation";
const BOOT_NEXT: &str = "/sys/firmware/efi/efivars/BootNext-8be4df61-93ca-11d2-aa0d-00e098032b8c";
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
            "Host data paths require private root-owned directories",
        ));
    }
    Ok(())
}

fn host_data() -> Result<(File, u64)> {
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
    let (host, id) = host_data()?;
    let relative = path.strip_prefix(HOST_DATA)?;
    let state = File::from(fs::openat(&host, relative, DIRECTORY, Mode::empty())?);
    private_directory(&state)?;
    if mount_id(&state)? != id {
        return Err(invalid("update state is outside the mounted Btrfs pool").into());
    }
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

fn matching_record(inbox: &File, name: &str, envelope: &[u8]) -> Result<Option<File>> {
    let flags =
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
    match fs::openat(inbox, name, flags, Mode::empty()) {
        Ok(existing) => {
            let existing = File::from(existing);
            private_file(&existing)?;
            let mut bytes = Vec::new();
            (&existing)
                .take((APPROVAL_LIMIT + 1) as u64)
                .read_to_end(&mut bytes)?;
            if bytes != envelope {
                return Err(invalid(if name == PENDING {
                    "another trial already occupies the Host inbox"
                } else {
                    "a different signed approval already occupies the Host inbox"
                })
                .into());
            }
            Ok(Some(existing))
        }
        Err(Errno::NOENT) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

pub fn check_install(transaction: &str, envelope: &[u8]) -> Result<bool> {
    require_idle()?;
    let (host, id) = host_data()?;
    let Some(inbox) = inbox(&host, id)? else {
        return Ok(false);
    };
    match fs::statat(&inbox, transaction, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => {
            return Err(invalid("the signed trial transaction has already been consumed").into());
        }
        Err(Errno::NOENT) => (),
        Err(error) => return Err(error.into()),
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
    authorize: &dyn Fn() -> Result<()>,
) -> Result<()> {
    let (host, id) = host_data()?;
    match fs::mkdirat(&host, "boot-trials", Mode::RUSR | Mode::WUSR | Mode::XUSR) {
        Ok(()) => host.sync_all()?,
        Err(Errno::EXIST) => (),
        Err(error) => return Err(error.into()),
    }
    let inbox = inbox(&host, id)?.ok_or_else(|| invalid("trial inbox disappeared"))?;
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
    publish_record(&inbox, PENDING, envelope, authorize)
}

pub fn publish_record(
    inbox: &File,
    name: &str,
    envelope: &[u8],
    authorize: &dyn Fn() -> Result<()>,
) -> Result<()> {
    write_record(inbox, name, envelope, fs::RenameFlags::NOREPLACE, authorize)
}

pub fn replace_record(
    inbox: &File,
    name: &str,
    envelope: &[u8],
    authorize: &dyn Fn() -> Result<()>,
) -> Result<()> {
    write_record(inbox, name, envelope, fs::RenameFlags::empty(), authorize)
}

fn write_record(
    inbox: &File,
    name: &str,
    envelope: &[u8],
    flags: fs::RenameFlags,
    authorize: &dyn Fn() -> Result<()>,
) -> Result<()> {
    let pinned = PathBuf::from(format!("/proc/self/fd/{}", inbox.as_raw_fd()));
    let mut record = tempfile::NamedTempFile::new_in(&pinned)?;
    record.write_all(envelope)?;
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
