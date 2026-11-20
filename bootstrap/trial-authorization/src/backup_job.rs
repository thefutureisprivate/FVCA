//! Signed scheduled backup policy and the read-only Host monitoring record.

use std::fmt;
use std::io;

use crate::{digest, invalid, number, uuid};

pub const POLICY: &str = "/run/fvca/vm-backup-job";
pub const OBSERVATION: &str = "vm-backup-observation";
pub const BYTES: usize = 2048;
const POLICY_HEADER: &str = "FVCA-BACKUP-JOB-1";
const OBSERVATION_HEADER: &str = "FVCA-BACKUP-OBSERVATION-1";
const MAX_OBJECTIVE: u64 = 31_536_000;

pub struct Policy<'a> {
    pub repository: &'a str,
    pub interval: u64,
    pub retry: u64,
    pub max_data_loss: u64,
    pub max_quiesce: u64,
    pub restore_objective: u64,
}

impl<'a> Policy<'a> {
    pub fn parse(text: &'a str) -> io::Result<Self> {
        let [
            header,
            repository,
            interval,
            retry,
            max_data_loss,
            max_quiesce,
            restore_objective,
        ] = ordered_fields(text)?;
        let policy = Self {
            repository: digest(repository, "repository=")?,
            interval: number(interval, "interval_seconds=")?,
            retry: number(retry, "retry_seconds=")?,
            max_data_loss: number(max_data_loss, "max_data_loss_seconds=")?,
            max_quiesce: number(max_quiesce, "max_quiesce_seconds=")?,
            restore_objective: number(restore_objective, "restore_objective_seconds=")?,
        };
        if header != POLICY_HEADER
            || !(5..=3600).contains(&policy.retry)
            || policy.retry > policy.interval
            || policy.interval > policy.max_data_loss
            || policy.max_data_loss > MAX_OBJECTIVE
            || !(1..=20).contains(&policy.max_quiesce)
            || !(1..=MAX_OBJECTIVE).contains(&policy.restore_objective)
        {
            return Err(invalid("invalid scheduled backup interval or objectives"));
        }
        Ok(policy)
    }

    pub fn require_repository(&self, repository: &str) -> io::Result<()> {
        if self.repository != repository {
            return Err(invalid("backup job names a different repository"));
        }
        Ok(())
    }
}

fn ordered_fields<const N: usize>(text: &str) -> io::Result<[&str; N]> {
    if text.len() > BYTES || text.contains('\r') {
        return Err(invalid("invalid backup record size or line endings"));
    }
    text.strip_suffix('\n')
        .ok_or_else(|| invalid("missing backup record terminator"))?
        .split('\n')
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| invalid("unexpected backup record fields"))
}

#[derive(Clone, Copy)]
pub struct RecoveryPoint<'a> {
    pub capture: &'a str,
    pub snapshot: &'a str,
    pub captured_at: u64,
}

pub struct Observation<'a> {
    pub filesystem: &'a str,
    pub repository: &'a str,
    pub observed_at: u64,
    pub last_upload: Option<RecoveryPoint<'a>>,
    pub pending: Option<&'a str>,
    pub attempt_failed: bool,
}

impl<'a> Observation<'a> {
    pub fn parse(text: &'a str) -> io::Result<Self> {
        let [
            header,
            filesystem,
            repository,
            observed,
            capture,
            snapshot,
            captured,
            pending,
            failed,
        ] = ordered_fields(text)?;
        let observed_at = number(observed, "observed_at=")?;
        let last_upload = match (capture, snapshot, captured) {
            ("capture=none", "snapshot=none", "captured_at=none") => None,
            (capture, snapshot, captured) => Some(RecoveryPoint {
                capture: capture_id(capture, "capture=")?,
                snapshot: digest(snapshot, "snapshot=")?,
                captured_at: number(captured, "captured_at=")?,
            }),
        };
        let pending = match pending {
            "pending=none" => None,
            pending => Some(capture_id(pending, "pending=")?),
        };
        let attempt_failed = match failed {
            "attempt_failed=0" => false,
            "attempt_failed=1" if pending.is_some() => true,
            _ => return Err(invalid("unexpected backup attempt status")),
        };
        let filesystem = capture_id(filesystem, "filesystem=")?;
        let repository = digest(repository, "repository=")?;
        if header != OBSERVATION_HEADER
            || last_upload.is_some_and(|point| point.captured_at > observed_at)
        {
            return Err(invalid("invalid backup observation version or times"));
        }
        Ok(Self {
            filesystem,
            repository,
            observed_at,
            last_upload,
            pending,
            attempt_failed,
        })
    }

    pub fn require_current(
        &self,
        policy: &Policy<'_>,
        filesystem: &str,
        now: u64,
    ) -> io::Result<()> {
        policy.require_repository(self.repository)?;
        // OnUnitInactiveSec is measured after the health service's 30 s deadline.
        // Allow its one-second timer accuracy and rounding of Unix seconds.
        if self.filesystem != filesystem
            || !now
                .checked_sub(self.observed_at)
                .is_some_and(|age| age <= policy.retry + 32)
        {
            return Err(invalid(
                "backup observation is stale or belongs to another filesystem",
            ));
        }
        Ok(())
    }
}

fn capture_id<'a>(line: &'a str, field: &str) -> io::Result<&'a str> {
    uuid(
        line.strip_prefix(field)
            .ok_or_else(|| invalid("missing backup identifier"))?,
    )
}

impl fmt::Display for Observation<'_> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            output,
            "{OBSERVATION_HEADER}\nfilesystem={}\nrepository={}\nobserved_at={}",
            self.filesystem, self.repository, self.observed_at
        )?;
        match self.last_upload {
            Some(point) => writeln!(
                output,
                "capture={}\nsnapshot={}\ncaptured_at={}",
                point.capture, point.snapshot, point.captured_at
            )?,
            None => writeln!(output, "capture=none\nsnapshot=none\ncaptured_at=none")?,
        }
        writeln!(
            output,
            "pending={}\nattempt_failed={}",
            self.pending.unwrap_or("none"),
            u8::from(self.attempt_failed)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binds_observations_to_current_pool_policy_and_time() -> io::Result<()> {
        let repository = "a".repeat(64);
        let policy_text = format!(
            "{POLICY_HEADER}\nrepository={repository}\ninterval_seconds=60\nretry_seconds=5\nmax_data_loss_seconds=75\nmax_quiesce_seconds=10\nrestore_objective_seconds=300\n"
        );
        let policy = Policy::parse(&policy_text)?;
        let pool = "367f5cbc-c46a-437d-af72-5d96d805d234";
        let capture = "aac8e4c2-431c-4150-bc6f-dcb88e8474c5";
        let pending = "bdab07f7-0021-493d-9f37-51259b56ca50";
        let snapshot = "b".repeat(64);
        let observation = Observation {
            filesystem: pool,
            repository: &repository,
            observed_at: 100,
            last_upload: Some(RecoveryPoint {
                capture,
                snapshot: &snapshot,
                captured_at: 90,
            }),
            pending: Some(pending),
            attempt_failed: true,
        };
        let text = observation.to_string();
        let parsed = Observation::parse(&text)?;
        parsed.require_current(&policy, pool, 137)?;
        assert_eq!(parsed.last_upload.map(|point| point.capture), Some(capture));
        assert!(parsed.attempt_failed);
        assert!(parsed.require_current(&policy, pool, 138).is_err());
        assert!(parsed.require_current(&policy, pool, 99).is_err());
        assert!(parsed.require_current(&policy, capture, 100).is_err());
        let wrong = text.replace(
            &format!("repository={repository}"),
            &format!("repository={snapshot}"),
        );
        assert!(
            Observation::parse(&wrong)?
                .require_current(&policy, pool, 100)
                .is_err()
        );
        for wrong in [
            text.replace("captured_at=90", "captured_at=101"),
            text.replace("captured_at=90", "captured_at=none"),
            text.replace(&format!("pending={pending}"), "pending=none"),
            format!("{text}secret=forbidden\n"),
        ] {
            assert!(Observation::parse(&wrong).is_err());
        }
        let empty = Observation {
            last_upload: None,
            pending: None,
            attempt_failed: false,
            ..observation
        }
        .to_string();
        assert!(Observation::parse(&empty)?.last_upload.is_none());
        Ok(())
    }
}
