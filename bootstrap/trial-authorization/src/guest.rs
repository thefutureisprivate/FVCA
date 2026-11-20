//! The exact direct-boot release selected by the Host and its independent trial authority.

use std::ffi::CStr;
use std::io;

use super::{digest, invalid, number, uuid};

pub const BOOT: &str = "/run/fvca/guest-boot";
pub const SERVICE_GUEST_UUID: &CStr = c"e629aa43-af11-47c6-aedc-a2dc47f1cc3a";
pub const SELECTION: &str = "/run/fvca/guest-launch";
pub const TRIAL_ENROLLMENT: &str = "/run/fvca/guest-trial-enrollment";
pub const STORE: &str = "/run/fvca/host-data/guest-updates";
pub const FENCE: &str = "guest-trial-inflight";
pub const ATTEMPT_LIMIT: u8 = 3;
pub const IMAGE_LIMIT: u64 = 4 * 1024 * 1024 * 1024;
pub const ENVELOPE_LIMIT: usize = 4096;
pub const ENROLLMENT_LIMIT: usize = 53;
pub const FILES: [&str; 9] = [
    "boot.efi",
    "linux",
    "initrd",
    "cmdline",
    "domain.xml",
    "core.raw",
    "runtime.raw",
    "release.json",
    "release.p7s",
];

pub struct Selection<'a> {
    pub bundle: &'a str,
    pub core: &'a str,
    pub runtime: &'a str,
    pub checksums: &'a str,
}

pub fn positive(value: &str) -> io::Result<u64> {
    number(value, "")
}

pub fn enrollment(record: &[u8]) -> io::Result<(&[u8; 32], u64)> {
    let (key, epoch) = record
        .split_first_chunk::<32>()
        .filter(|(key, _)| key.iter().any(|byte| *byte != 0))
        .ok_or_else(|| invalid("Guest trial authority is not enrolled"))?;
    let epoch = std::str::from_utf8(epoch)
        .map_err(io::Error::other)?
        .strip_suffix('\n')
        .ok_or_else(|| invalid("invalid enrolled Guest epoch"))?;
    Ok((key, positive(epoch)?))
}

pub fn parse(payload: &str) -> io::Result<Selection<'_>> {
    let mut lines = payload.splitn(5, '\n');
    let (Some("FVCA-GUEST-LAUNCH-1"), Some(bundle), Some(core), Some(runtime), Some(checksums)) = (
        lines.next(),
        lines.next(),
        lines.next(),
        lines.next(),
        lines.next(),
    ) else {
        return Err(invalid("invalid Guest launch selection"));
    };
    let mut inventory = checksums.split('\n');
    for name in FILES {
        let (hash, selected) = inventory
            .next()
            .and_then(|line| line.split_once("  "))
            .ok_or_else(|| invalid("incomplete Guest boot bundle inventory"))?;
        digest(hash, "")?;
        if selected != name {
            return Err(invalid("unexpected Guest boot bundle inventory"));
        }
    }
    if inventory.next() != Some("") || inventory.next().is_some() {
        return Err(invalid("unexpected fields in Guest launch selection"));
    }
    Ok(Selection {
        bundle: digest(bundle, "bundle=")?,
        core: digest(core, "core=")?,
        runtime: digest(runtime, "runtime=")?,
        checksums,
    })
}

pub struct Trial<'a> {
    pub transaction: &'a str,
    pub stable: &'a str,
    pub stable_epoch: u64,
    pub candidate_epoch: u64,
    pub deadline: u64,
    pub image_digest: &'a str,
    pub image_bytes: u64,
    pub launch: &'a str,
    pub selection: Selection<'a>,
    not_before: u64,
    expires: u64,
}

impl<'a> Trial<'a> {
    pub fn parse(body: &'a str) -> io::Result<Self> {
        if body.len() + 64 > ENVELOPE_LIMIT {
            return Err(invalid("Guest trial exceeds its size bound"));
        }
        let (authority, launch) = body.split_at(
            body.find("FVCA-GUEST-LAUNCH-1\n")
                .ok_or_else(|| invalid("missing Guest trial launch selection"))?,
        );
        let fields: Vec<_> = authority.split('\n').collect();
        let [
            "FVCA-GUEST-TRIAL-1",
            transaction,
            guest,
            stable,
            stable_epoch,
            candidate_epoch,
            from,
            until,
            deadline,
            "data=compatible",
            image_digest,
            image_bytes,
            "",
        ] = fields.as_slice()
        else {
            return Err(invalid("malformed Guest trial authorization"));
        };
        if guest.strip_prefix("guest=").map(str::as_bytes) != Some(SERVICE_GUEST_UUID.to_bytes()) {
            return Err(invalid("trial does not authorize this Service Guest"));
        }
        let stable = digest(stable, "stable_bundle=")?;
        let selection = parse(launch)?;
        let stable_epoch = number(stable_epoch, "stable_epoch=")?;
        let candidate_epoch = number(candidate_epoch, "candidate_epoch=")?;
        let not_before = number(from, "not_before=")?;
        let expires = number(until, "expires=")?;
        let deadline = number(deadline, "health_seconds=")?;
        let image_bytes = number(image_bytes, "candidate_image_bytes=")?;
        if stable == selection.bundle
            || candidate_epoch < stable_epoch
            || !expires
                .checked_sub(not_before)
                .is_some_and(|duration| (1..=86_400).contains(&duration))
            || !(10..=300).contains(&deadline)
            || image_bytes > IMAGE_LIMIT
            || !image_bytes.is_multiple_of(512)
        {
            return Err(invalid(
                "Guest trial exceeds its approved composition, epoch, time or size bounds",
            ));
        }
        Ok(Self {
            transaction: uuid(
                transaction
                    .strip_prefix("transaction=")
                    .ok_or_else(|| invalid("missing Guest trial transaction"))?,
            )?,
            stable,
            stable_epoch,
            candidate_epoch,
            deadline,
            image_digest: digest(image_digest, "candidate_image_sha256=")?,
            image_bytes,
            launch,
            selection,
            not_before,
            expires,
        })
    }

    pub fn require_fresh(&self, now: u64) -> io::Result<()> {
        if !(self.not_before..self.expires).contains(&now) {
            return Err(invalid(
                "Guest trial is outside its signed validity interval",
            ));
        }
        Ok(())
    }
}
