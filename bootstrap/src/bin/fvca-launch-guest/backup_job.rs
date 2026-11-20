//! Schedule and report the single boot-authorized Service Guest backup job.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use fvca_initrd_bootstrap::backup_policy;
use fvca_trial_authorization::backup_job::{self, Observation, RecoveryPoint};

use super::{Consistency, backup, btrfs, directory, invalid, lease, live, optional_record,
            private_directory, publish, read_record, recorded_capture, replace_record, restore, run, uuid};
use crate::{CAPTURE_LOCK, POOL, verify_pool};

const HEADER: &str = "FVCA-BACKUP-JOB-STATE-1";
const UNIT: &str = "fvca-backup-scheduled.service";

#[derive(Default)]
struct JobState {
    last: Option<String>,
    pending: Option<String>,
    attempted: u64,
    failed: bool,
}

impl JobState {
    fn load(dir: &Path) -> io::Result<Self> {
        let Some(text) = optional_record(&dir.join("state"))? else { return Ok(Self::default()); };
        let mut lines = text.lines();
        if lines.next() != Some(HEADER) || text.contains('\r') || !text.ends_with('\n') {
            return Err(invalid("unexpected scheduled backup journal version"));
        }
        let mut take = |key| lines.next().and_then(|line| line.strip_prefix(key))
            .ok_or_else(|| invalid("incomplete scheduled backup journal"));
        let id = |value| -> io::Result<Option<String>> {
            if value == "none" { Ok(None) } else { Ok(Some(uuid(value)?.to_owned())) }
        };
        let last = id(take("last=")?)?;
        let pending = id(take("pending=")?)?;
        let attempted = take("attempted=")?.parse::<u64>().map_err(io::Error::other)?;
        let failed = match take("failed=")? {
            "1" => true,
            "0" => false,
            _ => return Err(invalid("invalid scheduled backup result")),
        };
        if pending.is_none() && (attempted != 0 || failed) || pending.is_some() && (pending == last || attempted == 0)
            || lines.next().is_some()
        {
            return Err(invalid("inconsistent scheduled backup journal"));
        }
        Ok(Self { last, pending, attempted, failed })
    }

    fn save(&self, dir: &Path) -> io::Result<()> {
        let last = self.last.as_deref().unwrap_or("none");
        let pending = self.pending.as_deref().unwrap_or("none");
        replace_record(dir, "state", &format!("{HEADER}\nlast={last}\npending={pending}\nattempted={}\nfailed={}\n",
                                              self.attempted, u8::from(self.failed)))
    }

    fn due(&self, age: Option<u64>, now: u64, policy: &backup_job::Policy<'_>) -> io::Result<bool> {
        if self.pending.is_some() {
            Ok(elapsed(now, self.attempted)? >= policy.retry)
        } else {
            Ok(age.is_none_or(|seconds| seconds >= policy.interval))
        }
    }
}

struct Job<'a> {
    policy: backup_job::Policy<'a>,
    destination: backup_policy::Policy<'a>,
    fsid: String,
    dir: PathBuf,
}

struct Completion {
    capture: String,
    snapshot: String,
    captured: u64,
}

fn now() -> io::Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH).map_err(io::Error::other)?.as_secs())
}

fn elapsed(now: u64, earlier: u64) -> io::Result<u64> {
    now.checked_sub(earlier).ok_or_else(|| invalid("the backup job clock precedes its durable records"))
}

fn capture_path(id: &str) -> PathBuf {
    Path::new(POOL).join("captures").join("sets").join(id)
}

impl<'a> Job<'a> {
    fn open(text: &'a str, destination: &'a str, create: bool) -> io::Result<Self> {
        let destination = backup_policy::parse(destination)?;
        let policy = backup_job::Policy::parse(text)?;
        policy.require_repository(destination.repository)?;
        let fsid = btrfs::filesystem_uuid(&verify_pool()?)?;
        let mut dir = PathBuf::from(POOL);
        for part in ["captures", "scheduled", policy.repository] {
            dir.push(part);
            if create {
                directory(&dir)?;
            } else if dir.try_exists()? {
                private_directory(&dir)?;
            }
        }
        Ok(Self { policy, destination, fsid, dir })
    }

    fn completion(&self, id: &str) -> io::Result<Option<Completion>> {
        let path = capture_path(id);
        if !path.try_exists()? {
            return Ok(None);
        }
        private_directory(path.parent().expect("capture has a parent"))?;
        private_directory(&path)?;
        let receipt = path.join(format!("backup-{}", self.policy.repository));
        let Some(receipt) = optional_record(&receipt)? else { return Ok(None); };
        let manifest = read_record(&path.join("manifest"))?;
        let record = recorded_capture(&path, id, &self.fsid, &manifest)?;
        if !matches!(record.consistency, Consistency::Filesystem) {
            return Err(invalid("scheduled capture does not have the approved live consistency class"));
        }
        let snapshot = backup::received_snapshot(&receipt, id, record.digest, self.policy.repository)?;
        Ok(Some(Completion { capture: id.to_owned(), snapshot, captured: record.plan.captured }))
    }

    fn last(&self, state: &JobState) -> io::Result<Option<Completion>> {
        state.last.as_deref().map(|id| self.completion(id)?.ok_or_else(|| invalid("scheduled backup receipt is missing")))
            .transpose()
    }

    fn reusable(&self, id: &str) -> io::Result<bool> {
        let _transaction = lease(Path::new(CAPTURE_LOCK))?;
        restore::require_idle()?;
        let path = capture_path(id);
        if !path.try_exists()? {
            live::require_idle()?;
            return Ok(true);
        }
        private_directory(&path)?;
        if let Some(verified) = optional_record(&path.join("live-seal-verified"))? {
            if verified == "1\n" {
                return Ok(true);
            }
            return Err(invalid("invalid durable live seal acknowledgement"));
        }
        if live::can_reconcile(id)? {
            return Ok(true);
        }
        if path.join("snapshot").try_exists()? || path.join("sealed").try_exists()? {
            return Err(invalid("an interrupted capture has an unacknowledged seal and needs reconciliation"));
        }
        publish(&path, "scheduled-abandoned", &format!("{id}\n"))?;
        println!("FVCA_BACKUP_JOB_ABANDONED capture={id}");
        Ok(false)
    }

    fn finish(&self, complete: Completion) -> io::Result<()> {
        elapsed(now()?, complete.captured)?;
        let snapshot = complete.snapshot;
        let capture = complete.capture;
        JobState { last: Some(capture.clone()), ..JobState::default() }.save(&self.dir)?;
        println!("FVCA_BACKUP_JOB_COMPLETE capture={capture} snapshot={snapshot} captured={}", complete.captured);
        Ok(())
    }

    fn failed(&self, mut state: JobState, error: io::Error) -> io::Result<()> {
        state.attempted = now()?;
        state.failed = true;
        state.save(&self.dir)?;
        eprintln!("FVCA_BACKUP_JOB_ALERT partial capture={}", state.pending.as_deref().expect("attempt has an ID"));
        Err(error)
    }

    fn attempt(&self) -> io::Result<()> {
        let mut state = JobState::load(&self.dir)?;
        let clock = now()?;
        let last = self.last(&state)?;
        let age = last.map(|complete| elapsed(clock, complete.captured)).transpose()?;
        if !state.due(age, clock, &self.policy)? {
            return Ok(());
        }
        if let Some(id) = state.pending.as_deref() {
            if let Some(complete) = self.completion(id)?
                && !capture_path(id).join(format!("backup-pending-{}", self.policy.repository)).try_exists()?
            {
                return self.finish(complete);
            }
            match self.reusable(id) {
                Ok(true) => {}
                Ok(false) => state.pending = None,
                Err(error) => return self.failed(state, error),
            }
        }

        let id = match state.pending.take() {
            Some(id) => id,
            None => {
                let generated = fs::read_to_string("/proc/sys/kernel/random/uuid")?;
                uuid(generated.trim_end())?.to_owned()
            }
        };
        state.pending = Some(id.clone());
        state.attempted = now()?;
        state.failed = false;
        state.save(&self.dir)?;
        println!("FVCA_BACKUP_JOB_ATTEMPT capture={id}");
        let result = backup::upload_locked(&id, true, &self.destination)
            .and_then(|()| self.completion(&id)?.ok_or_else(|| invalid("upload left no finalized recovery receipt")));
        match result {
            Ok(complete) => self.finish(complete),
            Err(error) => self.failed(state, error),
        }
    }

    fn health(&self) -> io::Result<()> {
        let state = JobState::load(&self.dir)?;
        let pending = state.pending.as_deref();
        let last = match pending.map(|id| self.completion(id)).transpose()?.flatten() {
            Some(complete) => Some(complete),
            None => self.last(&state)?,
        };
        let clock = now()?;
        let age = last.as_ref().map(|complete| elapsed(clock, complete.captured)).transpose()?;
        let observation = Observation {
            filesystem: &self.fsid,
            repository: self.policy.repository,
            observed_at: clock,
            last_upload: last.as_ref().map(|complete| RecoveryPoint {
                capture: &complete.capture,
                snapshot: &complete.snapshot,
                captured_at: complete.captured,
            }),
            pending,
            attempt_failed: state.failed,
        };
        let observation = replace_record(Path::new("/run/fvca"), backup_job::OBSERVATION, &observation.to_string());
        let capture = last.as_ref().map_or("none", |complete| complete.capture.as_str());
        let snapshot = last.as_ref().map_or("none", |complete| complete.snapshot.as_str());
        let pending = pending.unwrap_or("none");
        println!("FVCA_BACKUP_JOB_STATUS repository={} last_capture={capture} last_snapshot={snapshot} age_seconds={} pending={pending} max_data_loss_seconds={} restore_objective_seconds={}",
                 self.policy.repository, age.map_or_else(|| "unknown".into(), |age| age.to_string()),
                 self.policy.max_data_loss, self.policy.restore_objective);
        if state.due(age, clock, &self.policy)? {
            run(Command::new("/usr/bin/systemctl").args(["start", "--no-block", UNIT]))?;
        }
        let missed = age.is_none_or(|seconds| seconds > self.policy.max_data_loss);
        if missed {
            eprintln!("FVCA_BACKUP_JOB_ALERT missed last_capture={capture} pending={pending}");
        }
        if state.failed {
            eprintln!("FVCA_BACKUP_JOB_ALERT partial capture={pending}");
        }
        observation?;
        if missed || state.failed {
            return Err(invalid("the scheduled backup requires attention"));
        }
        Ok(())
    }
}

pub(crate) fn operate(execute: bool) -> io::Result<()> {
    let text = fs::read_to_string(backup_job::POLICY)?;
    let destination = fs::read_to_string(backup_policy::POLICY)?;
    if execute {
        let _backup = lease(Path::new(backup::BACKUP_LOCK))?;
        Job::open(&text, &destination, true)?.attempt()
    } else {
        Job::open(&text, &destination, false)?.health()
    }
}
