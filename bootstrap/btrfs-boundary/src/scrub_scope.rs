//! Physical backing identities shared by scrub enrollment, execution and reporting.

use std::fs::OpenOptions;
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

pub const SCOPE_PATH: &str = "/run/fvca/storage-scrub";
pub const SUPPORT: &str = "/usr/lib/fvca/storage-scrub-enrollment-v2";
pub const SCHEMA: &str = "fvca-btrfs-scrub-v2";
pub const RECEIPT_LIMIT: u64 = 1024;
const SCOPE_LIMIT: u64 = 256;

pub struct Scope<'a> {
    pub target: &'a str,
    pub filesystem: &'a str,
    pub backing: &'a str,
}

fn invalid_scope() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid verified Btrfs scrub scope",
    )
}

fn uuid(text: &str) -> bool {
    text.len() == 36
        && text.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
}

impl<'a> Scope<'a> {
    pub fn parse(text: &'a str) -> io::Result<Self> {
        let [target, filesystem, backing, ""] = text.splitn(4, '\n').collect::<Vec<_>>()[..] else {
            return Err(invalid_scope());
        };
        let valid = match target {
            "/run/fvca/guest-data" => uuid(backing),
            "/run/fvca/host-data" => backing.split_once(',').is_some_and(|(a, b)| {
                let Some(((part_a, luks_a), (part_b, luks_b))) =
                    a.split_once(':').zip(b.split_once(':'))
                else {
                    return false;
                };
                part_a < part_b
                    && luks_a != luks_b
                    && [part_a, part_b, luks_a, luks_b].into_iter().all(uuid)
            }),
            _ => false,
        };
        if !uuid(filesystem) || !valid {
            return Err(invalid_scope());
        }
        Ok(Self {
            target,
            filesystem,
            backing,
        })
    }

    pub fn receipt_prefix(&self) -> String {
        format!(
            "{{\"schema\":\"{SCHEMA}\",\"filesystem_uuid\":\"{}\",\"storage_members\":\"{}\",",
            self.filesystem, self.backing,
        )
    }

    /// Only the canonical header written by the scrub worker can defer a scrub.
    pub fn covers(&self, mut receipt: impl Read, size: u64) -> io::Result<bool> {
        let prefix = self.receipt_prefix();
        if size > RECEIPT_LIMIT || size < prefix.len() as u64 {
            return Ok(false);
        }
        let mut observed = vec![0; prefix.len()];
        receipt.read_exact(&mut observed)?;
        Ok(observed == prefix.as_bytes())
    }
}

pub fn read_selection() -> io::Result<String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(0o400000 | 0o4000) // O_NOFOLLOW | O_NONBLOCK on Linux.
        .open(SCOPE_PATH)?;
    let info = file.metadata()?;
    if !info.is_file()
        || info.uid() != 0
        || info.gid() != 0
        || info.nlink() != 1
        || info.mode() & 0o022 != 0
        || info.len() > SCOPE_LIMIT
    {
        return Err(invalid_scope());
    }
    let mut text = String::new();
    file.take(SCOPE_LIMIT + 1).read_to_string(&mut text)?;
    if text.len() as u64 > SCOPE_LIMIT {
        return Err(invalid_scope());
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FSID: &str = "24c81473-0929-48ed-8729-47cf01f65bba";
    const PART_A: &str = "4485c51b-9500-4460-a72a-7fb0c98bc604";
    const PART_B: &str = "72d7b824-717b-401f-8133-7d6ef53e1c7e";
    const PART_SPARE: &str = "ec803886-0e97-4eef-b90f-e61491ca1b30";
    const LUKS_A: &str = "8c3a4b4f-18af-44ed-b62b-18ad3de6984c";
    const LUKS_B: &str = "ad176afb-2775-4bca-9a70-45eb7e67fbc2";
    const LUKS_SPARE: &str = "c0089b3a-4069-4fcb-b055-8318bef54dfb";

    fn host(part_b: &str, luks_b: &str) -> String {
        format!("/run/fvca/host-data\n{FSID}\n{PART_A}:{LUKS_A},{part_b}:{luks_b}\n")
    }

    #[test]
    fn repaired_mirror_cannot_reuse_recent_scrub_receipt() {
        let original = host(PART_B, LUKS_B);
        let original = Scope::parse(&original).unwrap();
        let receipt = format!("{}\"completed_members\":2}}\n", original.receipt_prefix());
        let length = receipt.len() as u64;
        assert!(original.covers(receipt.as_bytes(), length).unwrap());
        for changed in [host(PART_SPARE, LUKS_SPARE), host(PART_B, LUKS_SPARE)] {
            let changed = Scope::parse(&changed).unwrap();
            assert!(!changed.covers(receipt.as_bytes(), length).unwrap());
        }
        let legacy =
            format!("{{\"schema\":\"fvca-btrfs-scrub-v1\",\"filesystem_uuid\":\"{FSID}\"}}");
        assert!(
            !original
                .covers(legacy.as_bytes(), legacy.len() as u64)
                .unwrap()
        );
        assert!(
            !original
                .covers(receipt.as_bytes(), RECEIPT_LIMIT + 1)
                .unwrap()
        );
    }

    #[test]
    fn scope_requires_canonical_role_and_backing() {
        let guest = format!("/run/fvca/guest-data\n{FSID}\n{PART_A}\n");
        assert_eq!(Scope::parse(&guest).unwrap().backing, PART_A);
        assert!(Scope::parse(guest.trim_end()).is_err());
        assert!(Scope::parse(&host(PART_A, LUKS_B)).is_err());
        assert!(Scope::parse(&host(PART_B, LUKS_A)).is_err());
        assert!(
            Scope::parse(&format!(
                "/run/fvca/host-data\n{FSID}\n{PART_B}:{LUKS_B},{PART_A}:{LUKS_A}\n"
            ))
            .is_err()
        );
        assert!(
            Scope::parse(&format!(
                "/run/fvca/guest-data\n{FSID}\n{PART_A}:{LUKS_A}\n"
            ))
            .is_err()
        );
    }
}
