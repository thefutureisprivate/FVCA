//! Bind the signed initrd's automatic unlock receipt to this boot's live state.

use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use fvca_trial_authorization::firmware::{VERIFIED_BOOT, VERIFIED_BOOT_LIMIT, VerifiedBoot};
use rustix::fs::{StatVfsMountFlags, fstatvfs};
use serde::{Deserialize, Serialize};

use super::{capsule, uuid};
use crate::{Result, handoff, invalid, state, valid_digest};

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub(super) enum Evidence {
    Observed(Box<Observation>),
    Unavailable { reason: String },
}

#[derive(Serialize)]
pub(super) struct Observation {
    boot_entry: u16,
    #[serde(flatten)]
    pub(super) policy: Policy,
    pub(super) storage_error_free: bool,
    mirror_members: [MirrorMember; 2],
}

#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Policy {
    esp: String,
    core: String,
    runtime: String,
    pub(super) epoch: u64,
    epoch_policy_sha256: String,
    pub(super) tpm_floor: u64,
    pcr7_sha256: String,
    pub(super) filesystem: String,
    storage_policy_sha256: String,
}

impl Policy {
    pub(super) fn valid(&self) -> bool {
        uuid(&self.esp)
            && uuid(&self.filesystem)
            && (1..=self.epoch).contains(&self.tpm_floor)
            && self.pcr7_sha256.bytes().any(|byte| byte != b'0')
            && [
                &self.core,
                &self.runtime,
                &self.epoch_policy_sha256,
                &self.pcr7_sha256,
                &self.storage_policy_sha256,
            ]
            .into_iter()
            .all(|field| valid_digest(field))
    }
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
        policy: Policy {
            esp: receipt.esp.to_owned(),
            core: receipt.core.to_owned(),
            runtime: receipt.runtime.to_owned(),
            epoch: receipt.epoch,
            epoch_policy_sha256: receipt.epoch_policy_sha256.to_owned(),
            tpm_floor: receipt.tpm_floor,
            pcr7_sha256: receipt.pcr7_sha256.to_owned(),
            filesystem,
            storage_policy_sha256: receipt.storage_policy_sha256.to_owned(),
        },
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
    use crate::firmware::transition::{Status, compare};

    #[test]
    fn qualifies_only_the_expected_policy_with_healthy_mirror_members() -> Result<()> {
        let policy = |storage: &str| Policy {
            esp: "d0d2fd6b-ee28-4034-a022-b3da25744690".into(),
            core: "7".repeat(64),
            runtime: "8".repeat(64),
            epoch: 10,
            epoch_policy_sha256: "9".repeat(64),
            tpm_floor: 10,
            pcr7_sha256: "a".repeat(64),
            filesystem: "dfc379cc-7f43-4c4d-8b3b-e9b34c112712".into(),
            storage_policy_sha256: storage.repeat(64),
        };
        let member = |id| MirrorMember {
            id,
            write_errors: 0,
            read_errors: 0,
            flush_errors: 0,
            corruption_errors: 0,
            generation_errors: 0,
        };
        let observation = |storage, healthy| {
            Evidence::Observed(Box::new(Observation {
                boot_entry: 1,
                policy: policy(storage),
                storage_error_free: healthy,
                mirror_members: [member(1), member(2)],
            }))
        };
        let qualified = policy("b");
        let current = observation("b", true);
        assert!(matches!(compare(&qualified, &current), Status::Matched));
        assert_eq!(
            serde_json::to_value(&current)?["storage_policy_sha256"],
            "b".repeat(64)
        );
        assert!(matches!(
            compare(&qualified, &observation("a", true)),
            Status::Blocked { reason } if reason.contains("exact qualified boot")
        ));
        assert!(matches!(
            compare(&qualified, &observation("b", false)),
            Status::Blocked { reason } if reason.contains("persistent errors")
        ));
        Ok(())
    }

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
