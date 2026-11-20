//! The periodic live backup job selected by the signed Hypervisor UKI.

use std::fs;
use std::io;
use std::os::unix::fs::symlink;
use std::path::Path;

use fvca_trial_authorization::backup_job::{POLICY, Policy};

use crate::{backup_policy, invalid, retention_policy};

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
    let policy = Policy::parse(&text)?;
    policy.require_repository(backup_policy::parse(&destination)?.repository)?;
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
    fs::write(POLICY, text)?;
    let wants = units.join("fvca-base.target.wants");
    fs::create_dir_all(&wants)?;
    symlink("/usr/lib/systemd/system/fvca-backup-health.timer", wants.join("fvca-backup-health.timer"))
}
