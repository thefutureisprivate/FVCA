//! The periodic live backup job selected by the signed Hypervisor UKI.

use std::fs;
use std::io;
use std::os::unix::fs::symlink;
use std::path::Path;

use crate::{backup_policy, invalid, retention_policy, runtime};

pub const JOB: &str = "/run/fvca/vm-backup-job";

pub struct Policy<'a> {
    pub repository: &'a str,
    pub interval: u64,
    pub retry: u64,
    pub max_data_loss: u64,
    pub max_quiesce: u64,
    pub restore_objective: u64,
}

pub fn parse<'a>(text: &'a str, repository: &str) -> io::Result<Policy<'a>> {
    if text.len() > 2048 || !text.ends_with('\n') || text.contains('\r') {
        return Err(invalid("invalid scheduled backup policy size or terminator"));
    }
    let mut lines = text.lines();
    if lines.next() != Some("FVCA-BACKUP-JOB-1") {
        return Err(invalid("unexpected scheduled backup policy version"));
    }
    let mut take = |key| lines.next().and_then(|line| line.strip_prefix(key))
        .ok_or_else(|| invalid("incomplete scheduled backup policy"));
    let selected = runtime::hash(take("repository=")?)?;
    let number = |value: &str| value.parse::<u64>().ok().filter(|n| n.to_string() == value)
        .ok_or_else(|| invalid("invalid signed backup job budget"));
    let interval = number(take("interval_seconds=")?)?;
    let retry = number(take("retry_seconds=")?)?;
    let max_data_loss = number(take("max_data_loss_seconds=")?)?;
    let max_quiesce = number(take("max_quiesce_seconds=")?)?;
    let restore_objective = number(take("restore_objective_seconds=")?)?;
    if lines.next().is_some() || selected != repository || !(5..=3600).contains(&retry)
        || retry > interval || interval > max_data_loss || max_data_loss > 31_536_000
        || !(1..=20).contains(&max_quiesce) || !(1..=31_536_000).contains(&restore_objective)
    {
        return Err(invalid("invalid scheduled backup repository, interval or objectives"));
    }
    Ok(Policy { repository: selected, interval, retry, max_data_loss, max_quiesce, restore_objective })
}

pub fn activate_if_selected(recovering: bool) -> io::Result<()> {
    let text = match fs::read_to_string("/usr/lib/fvca/vm-backup-job") {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if recovering {
        return Err(invalid("a recovery Hypervisor cannot schedule ordinary backups"));
    }
    if !Path::new(retention_policy::POLICY).try_exists()? {
        return Err(invalid("scheduled backup requires a signed local retention policy"));
    }
    let destination = fs::read_to_string(backup_policy::POLICY)?;
    let policy = parse(&text, backup_policy::parse(&destination)?.repository)?;
    let units = Path::new("/run/systemd/system");
    for (unit, settings) in [
        ("fvca-backup-health.timer", format!("[Timer]\nOnUnitInactiveSec={}s\n", policy.retry)),
        ("fvca-live-window@.service", format!("[Service]\nTimeoutStartSec={}s\n", policy.max_quiesce)),
        ("fvca-live-recover@.timer", format!("[Timer]\nOnActiveSec=\nOnActiveSec={}s\n", policy.max_quiesce)),
    ] {
        let dropin = units.join(format!("{unit}.d"));
        fs::create_dir_all(&dropin)?;
        fs::write(dropin.join("30-backup-job.conf"), settings)?;
    }
    fs::write(JOB, text)?;
    let wants = units.join("fvca-base.target.wants");
    fs::create_dir_all(&wants)?;
    symlink("/usr/lib/systemd/system/fvca-backup-health.timer", wants.join("fvca-backup-health.timer"))
}
