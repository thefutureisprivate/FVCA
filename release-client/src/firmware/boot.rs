//! Bind the signed initrd's automatic unlock receipt to this boot's live state.

use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use fvca_trial_authorization::firmware::{VERIFIED_BOOT, VERIFIED_BOOT_LIMIT, VerifiedBoot};
use rustix::fs::{StatVfsMountFlags, fstatvfs};
use serde::Serialize;

use super::capsule;
use crate::{Result, handoff, invalid, state};

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub(super) enum Evidence {
    Observed(Box<Observation>),
    Unavailable { reason: String },
}

#[derive(Serialize)]
pub(super) struct Observation {
    boot_entry: u16,
    esp: String,
    core: String,
    runtime: String,
    epoch: u64,
    epoch_policy_sha256: String,
    filesystem: String,
    storage_policy_sha256: String,
    storage_error_free: bool,
    mirror_members: [MirrorMember; 2],
}

#[derive(Serialize)]
struct MirrorMember {
    id: u64,
    write_errors: u64,
    read_errors: u64,
    flush_errors: u64,
    corruption_errors: u64,
    generation_errors: u64,
}

impl MirrorMember {
    fn error_free(&self) -> bool {
        [
            self.write_errors,
            self.read_errors,
            self.flush_errors,
            self.corruption_errors,
            self.generation_errors,
        ] == [0; 5]
    }
}

pub(super) fn inspect(pool: &File, boot_id: &str) -> Evidence {
    collect(pool, boot_id).unwrap_or_else(|error| Evidence::Unavailable {
        reason: error.to_string(),
    })
}

fn collect(pool: &File, boot_id: &str) -> Result<Evidence> {
    let file = state::open_regular(Path::new(VERIFIED_BOOT)).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("verified firmware boot receipt: {error}"),
        )
    })?;
    handoff::private_file(&file)?;
    let mut bytes = Vec::new();
    file.take(VERIFIED_BOOT_LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > VERIFIED_BOOT_LIMIT {
        return Err(invalid("verified firmware boot receipt exceeds its size bound").into());
    }
    let receipt = VerifiedBoot::parse(std::str::from_utf8(&bytes)?)?;
    let filesystem = fvca_btrfs_boundary::filesystem_uuid(pool)?;
    if receipt.boot_id != boot_id || receipt.filesystem != filesystem {
        return Err(invalid(
            "verified firmware boot receipt differs from the current boot or pool",
        )
        .into());
    }
    let flags = fstatvfs(pool)?.f_flag;
    let required = StatVfsMountFlags::NODEV | StatVfsMountFlags::NOSUID | StatVfsMountFlags::NOEXEC;
    if !flags.contains(required) || flags.contains(StatVfsMountFlags::RDONLY) {
        return Err(invalid("Host data pool lacks its expected writable mount flags").into());
    }
    fvca_btrfs_boundary::require_raid1_profiles(pool)?;
    let mirror_members = mirror_members(Path::new("/sys/fs/btrfs"), &filesystem)?;
    if state::read(Path::new("/sys/fs/selinux/enforce"), 2)? != b"1"
        || state::read(
            Path::new("/sys/module/dm_verity/parameters/require_signatures"),
            2,
        )? != b"Y\n"
    {
        return Err(invalid(
            "firmware recovery requires enforcing SELinux and signed verity roots",
        )
        .into());
    }
    let boot_entry = capsule::verify_ordinary_boot()?;
    Ok(Evidence::Observed(Box::new(Observation {
        boot_entry,
        esp: receipt.esp.to_owned(),
        core: receipt.core.to_owned(),
        runtime: receipt.runtime.to_owned(),
        epoch: receipt.epoch,
        epoch_policy_sha256: receipt.epoch_policy_sha256.to_owned(),
        filesystem,
        storage_policy_sha256: receipt.storage_policy_sha256.to_owned(),
        storage_error_free: mirror_members.iter().all(MirrorMember::error_free),
        mirror_members,
    })))
}

fn counter(text: &str) -> Result<u64> {
    if text.bytes().all(|byte| byte.is_ascii_digit()) && (text == "0" || !text.starts_with('0')) {
        return Ok(text.parse()?);
    }
    Err(invalid("invalid Btrfs device counter").into())
}

fn mirror_members(sysfs: &Path, fsid: &str) -> Result<[MirrorMember; 2]> {
    let entries = fs::read_dir(sysfs.join(fsid).join("devinfo"))?
        .take(3)
        .collect::<std::io::Result<Vec<_>>>()?;
    let [first, second] = entries.as_slice() else {
        return Err(invalid("expected exactly two live Btrfs mirror members").into());
    };
    let mut members = [member(first, fsid)?, member(second, fsid)?];
    members.sort_unstable_by_key(|member| member.id);
    Ok(members)
}

fn member(entry: &fs::DirEntry, fsid: &str) -> Result<MirrorMember> {
    let id = counter(
        entry
            .file_name()
            .to_str()
            .ok_or_else(|| invalid("invalid Btrfs device ID"))?,
    )?;
    if id == 0 || !entry.file_type()?.is_dir() {
        return Err(invalid("invalid Btrfs mirror member").into());
    }
    let path = entry.path();
    if state::read(&path.join("fsid"), 37)? != format!("{fsid}\n").as_bytes()
        || state::read(&path.join("in_fs_metadata"), 2)? != b"1\n"
        || state::read(&path.join("missing"), 2)? != b"0\n"
        || state::read(&path.join("replace_target"), 2)? != b"0\n"
        || state::read(&path.join("writeable"), 2)? != b"1\n"
    {
        return Err(invalid(&format!(
            "Btrfs mirror member {id} is unavailable, foreign, or under replacement"
        ))
        .into());
    }
    let raw = state::read(&path.join("error_stats"), 256)?;
    let stats = std::str::from_utf8(&raw)?
        .strip_suffix('\n')
        .ok_or_else(|| invalid("unterminated Btrfs device error statistics"))?;
    let mut lines = stats.split('\n');
    let mut read_count = |field| {
        let value = lines
            .next()
            .and_then(|line| line.strip_prefix(field))
            .ok_or_else(|| invalid("malformed Btrfs device error statistics"))?;
        counter(value)
    };
    let result = MirrorMember {
        id,
        write_errors: read_count("write_errs ")?,
        read_errors: read_count("read_errs ")?,
        flush_errors: read_count("flush_errs ")?,
        corruption_errors: read_count("corruption_errs ")?,
        generation_errors: read_count("generation_errs ")?,
    };
    if lines.next().is_some() {
        return Err(invalid("unexpected extra Btrfs device error statistics").into());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_two_current_writable_members_and_preserves_error_counts() -> Result<()> {
        const FSID: &str = "3c0fcac2-d113-45b7-83bd-7eead418f2ed";
        let root = tempfile::tempdir()?;
        let devices = root.path().join(FSID).join("devinfo");
        for (id, errors) in [("9", 0), ("2", 3)] {
            let path = devices.join(id);
            fs::create_dir_all(&path)?;
            fs::write(path.join("fsid"), format!("{FSID}\n"))?;
            for (attribute, value) in [
                ("in_fs_metadata", "1\n"),
                ("missing", "0\n"),
                ("replace_target", "0\n"),
                ("writeable", "1\n"),
            ] {
                fs::write(path.join(attribute), value)?;
            }
            fs::write(
                path.join("error_stats"),
                format!(
                    "write_errs 0\nread_errs {errors}\nflush_errs 0\ncorruption_errs 0\ngeneration_errs 0\n"
                ),
            )?;
        }
        let [first, second] = mirror_members(root.path(), FSID)?;
        assert_eq!((first.id, first.read_errors), (2, 3));
        assert!(!first.error_free());
        assert_eq!(second.id, 9);
        assert!(second.error_free());
        fs::create_dir(devices.join("14"))?;
        assert!(mirror_members(root.path(), FSID).is_err());
        fs::remove_dir(devices.join("14"))?;
        fs::write(devices.join("2/missing"), "1\n")?;
        assert!(mirror_members(root.path(), FSID).is_err());
        fs::write(devices.join("2/missing"), "0\n")?;
        fs::write(devices.join("2/error_stats"), "invalid\n")?;
        assert!(mirror_members(root.path(), FSID).is_err());
        Ok(())
    }
}
