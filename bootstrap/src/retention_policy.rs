//! Local capture retention selected by the authenticated Hypervisor UKI.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::os::unix::fs::symlink;
use std::path::Path;

use crate::{backup_policy, invalid, recovery, runtime};

pub const POLICY: &str = "/run/fvca/vm-retention-policy";

pub struct Policy<'a> {
    pub repository: &'a str,
    pub keep_min: usize,
    pub keep_max: usize,
    pub max_age_seconds: u64,
    pub min_data_bytes: u64,
    pub min_metadata_bytes: u64,
    pub protected: BTreeSet<&'a str>,
}

pub fn parse(text: &str) -> io::Result<Policy<'_>> {
    if text.len() > 8192 || !text.ends_with('\n') || text.contains('\r') {
        return Err(invalid("invalid local retention policy size or terminator"));
    }
    let mut lines = text.lines();
    if lines.next() != Some("FVCA-LOCAL-RETENTION-1") {
        return Err(invalid("unexpected local retention policy version"));
    }
    let mut take = |name| lines.next().and_then(|line| line.strip_prefix(name))
        .ok_or_else(|| invalid("incomplete local retention policy"));
    let repository = runtime::hash(take("repository=")?)?;
    let number = |value: &str| value.parse::<u64>().ok().filter(|n| n.to_string() == value)
        .ok_or_else(|| invalid("invalid signed retention budget"));
    let keep_min = usize::try_from(number(take("keep_min=")?)?).map_err(io::Error::other)?;
    let keep_max = usize::try_from(number(take("keep_max=")?)?).map_err(io::Error::other)?;
    let max_age_seconds = number(take("max_age_seconds=")?)?;
    let min_data_bytes = number(take("min_data_bytes=")?)?;
    let min_metadata_bytes = number(take("min_metadata_bytes=")?)?;
    if keep_min == 0 || keep_max < keep_min || keep_max > 4096 || max_age_seconds == 0
        || min_data_bytes == 0 || min_metadata_bytes == 0
    {
        return Err(invalid("unexpected local retention age, count or space limits"));
    }
    let mut protected = BTreeSet::new();
    for line in lines {
        let id = recovery::uuid(line.strip_prefix("protect=").ok_or_else(|| invalid("unexpected retention field"))?)?;
        if !protected.insert(id) {
            return Err(invalid("duplicate protected capture"));
        }
    }
    Ok(Policy { repository, keep_min, keep_max, max_age_seconds, min_data_bytes, min_metadata_bytes, protected })
}

pub fn activate_if_selected() -> io::Result<()> {
    let text = match fs::read_to_string("/usr/lib/fvca/vm-retention-policy") {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let policy = parse(&text)?;
    let destination = fs::read_to_string(backup_policy::POLICY)?;
    if backup_policy::parse(&destination)?.repository != policy.repository {
        return Err(invalid("local expiry must be bound to the authorized backup repository"));
    }
    fs::write(POLICY, text)?;
    let wants = Path::new("/run/systemd/system/fvca-base.target.wants");
    fs::create_dir_all(wants)?;
    symlink("/usr/lib/systemd/system/fvca-capture-retention.timer", wants.join("fvca-capture-retention.timer"))
}
