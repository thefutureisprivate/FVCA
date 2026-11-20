//! Read bounded kernel observations from the authenticated Host pool.

use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use fvca_btrfs_boundary::SpaceUsage;
use fvca_trial_authorization::backup_job;
use rustix::fs::{StatVfsMountFlags, fstatvfs};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::Semaphore;
use tokio::task::spawn_blocking;

use super::protocol::{Refusal, current_time};
use crate::{Result, handoff, invalid, state, valid_uuid};

static ACTIVE: Semaphore = Semaphore::const_new(1);

fn space(usage: SpaceUsage) -> Value {
    json!({"total_bytes": usage.total, "used_bytes": usage.used})
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ScrubOutcome {
    InProgressOrInterrupted,
    Completed,
    Cancelled,
    Failed,
    Uncorrectable,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ScrubReport {
    schema: String,
    filesystem_uuid: String,
    boot_id: String,
    started_at: u64,
    finished_at: u64,
    outcome: ScrubOutcome,
    members: u8,
    completed_members: u8,
    data_bytes: u64,
    metadata_bytes: u64,
    no_checksum_blocks: u64,
    corrected_errors: u64,
    uncorrectable_errors: u64,
    allocation_errors: u64,
}

fn last_scrub(fsid: &str) -> Result<Option<ScrubReport>> {
    const DIRECTORY: &str = "/run/fvca/host-data/.fvca-scrub";
    let _directory = handoff::require_pool_directory(Path::new(DIRECTORY))?;
    let file = match state::open_regular(&Path::new(DIRECTORY).join("report.json")) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    handoff::private_file(&file)?;
    let mut bytes = Vec::new();
    file.take(1025).read_to_end(&mut bytes)?;
    if bytes.len() > 1024 {
        return Err(invalid("scrub receipt exceeds its size limit").into());
    }
    let report: ScrubReport = serde_json::from_slice(&bytes)?;
    if report.schema != "fvca-btrfs-scrub-v1"
        || report.filesystem_uuid != fsid
        || !valid_uuid(&report.boot_id)
        || report.started_at == 0
        || report.members != 2
        || report.completed_members > report.members
        || match report.outcome {
            ScrubOutcome::InProgressOrInterrupted => report.finished_at != 0,
            _ => report.finished_at < report.started_at,
        }
    {
        return Err(invalid("scrub receipt does not match the current Host pool").into());
    }
    Ok(Some(report))
}

fn report() -> Result<Value> {
    let (pool, _) = handoff::host_data()?;
    let health = fvca_btrfs_boundary::mirror_health(&pool)?;
    let history = last_scrub(&health.filesystem_uuid);
    let scrub_history_unavailable = history.is_err();
    let devices = health.members.map(|member| {
        json!({
            "id": member.id,
            "physical_bytes": member.physical_bytes,
            "allocated_bytes": member.allocated_bytes,
            "write_errors": member.write_errors,
            "read_errors": member.read_errors,
            "flush_errors": member.flush_errors,
            "corruption_errors": member.corruption_errors,
            "generation_errors": member.generation_errors,
        })
    });
    Ok(json!({
        "filesystem": "btrfs",
        "filesystem_uuid": health.filesystem_uuid,
        "profile": "raid1",
        "read_only": fstatvfs(&pool)?.f_flag.contains(StatVfsMountFlags::RDONLY),
        "data": space(health.data),
        "metadata": space(health.metadata),
        "system": space(health.system),
        "members": devices,
        "last_scrub": history.ok().flatten(),
        "scrub_history_unavailable": scrub_history_unavailable,
    }))
}

async fn observe<T: Send + 'static>(
    report: fn() -> Result<T>,
    refusal: Refusal,
) -> std::result::Result<T, Refusal> {
    let permit = ACTIVE.try_acquire().map_err(|_| refusal)?;
    // Hold the permit in the worker if the network request times out while
    // waiting for the filesystem. Storage I/O cannot block the broker loop.
    spawn_blocking(move || {
        let _permit = permit;
        report()
    })
    .await
    .map_err(|_| refusal)?
    .map_err(|_| refusal)
}

pub(super) async fn read() -> std::result::Result<Value, Refusal> {
    observe(report, Refusal::HostStorageHealthUnavailable).await
}

#[derive(Serialize)]
struct VerifiedUpload {
    capture: String,
    repository_snapshot: String,
    captured_at: u64,
    age_seconds: u64,
}

#[derive(Serialize)]
pub(super) struct ScheduledBackup {
    repository: String,
    observed_at: u64,
    last_verified_upload: Option<VerifiedUpload>,
    pending_capture: Option<String>,
    attempt_failed: bool,
    max_data_loss_seconds: u64,
    data_loss_window_missed: bool,
    restore_objective_seconds: u64,
}

fn backup_text(file: File) -> Result<String> {
    let mut text = String::new();
    file.take((backup_job::BYTES + 1) as u64)
        .read_to_string(&mut text)?;
    if text.len() > backup_job::BYTES {
        return Err(invalid("backup record exceeds its size bound").into());
    }
    Ok(text)
}

fn backup_report() -> Result<Option<ScheduledBackup>> {
    let enrollment = match state::open_regular(Path::new(backup_job::POLICY)) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let meta = enrollment.metadata()?;
    if meta.uid() != 0 || meta.gid() != 0 || meta.nlink() != 1 || meta.mode() & 0o7022 != 0 {
        return Err(invalid("invalid scheduled backup enrollment file").into());
    }
    let enrollment = backup_text(enrollment)?;
    let policy = backup_job::Policy::parse(&enrollment)?;
    let file = state::open_regular(&Path::new("/run/fvca").join(backup_job::OBSERVATION))?;
    handoff::private_file(&file)?;
    let text = backup_text(file)?;
    let observation = backup_job::Observation::parse(&text)?;
    let (pool, _) = handoff::host_data()?;
    let filesystem = fvca_btrfs_boundary::filesystem_uuid(&pool)?;
    let now = current_time()?;
    observation.require_current(&policy, &filesystem, now)?;
    let point = observation.last_upload.map(|point| VerifiedUpload {
        capture: point.capture.to_owned(),
        repository_snapshot: point.snapshot.to_owned(),
        captured_at: point.captured_at,
        age_seconds: now - point.captured_at,
    });
    Ok(Some(ScheduledBackup {
        repository: policy.repository.to_owned(),
        observed_at: observation.observed_at,
        data_loss_window_missed: point
            .as_ref()
            .is_none_or(|point| point.age_seconds > policy.max_data_loss),
        last_verified_upload: point,
        pending_capture: observation.pending.map(str::to_owned),
        attempt_failed: observation.attempt_failed,
        max_data_loss_seconds: policy.max_data_loss,
        restore_objective_seconds: policy.restore_objective,
    }))
}

pub(super) async fn backup() -> std::result::Result<Option<ScheduledBackup>, Refusal> {
    observe(backup_report, Refusal::HostBackupStatusUnavailable).await
}
