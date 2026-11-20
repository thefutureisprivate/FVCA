//! Read bounded kernel observations from the authenticated Host pool.

use std::io::{self, Read};
use std::path::Path;

use fvca_btrfs_boundary::SpaceUsage;
use rustix::fs::{StatVfsMountFlags, fstatvfs};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::Semaphore;
use tokio::task::spawn_blocking;

use super::protocol::Refusal;
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

pub(super) async fn read() -> std::result::Result<Value, Refusal> {
    let permit = ACTIVE
        .try_acquire()
        .map_err(|_| Refusal::HostStorageHealthUnavailable)?;
    // Hold the permit in the worker if the network request times out while
    // waiting for the filesystem. Storage I/O cannot block the broker loop.
    spawn_blocking(move || {
        let _permit = permit;
        report()
    })
    .await
    .map_err(|_| Refusal::HostStorageHealthUnavailable)?
    .map_err(|_| Refusal::HostStorageHealthUnavailable)
}
