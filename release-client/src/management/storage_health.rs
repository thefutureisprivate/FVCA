//! Read bounded kernel observations from the authenticated Host pool.

use fvca_btrfs_boundary::SpaceUsage;
use rustix::fs::{StatVfsMountFlags, fstatvfs};
use serde_json::{Value, json};
use tokio::sync::Semaphore;
use tokio::task::spawn_blocking;

use super::protocol::Refusal;
use crate::{Result, handoff};

static ACTIVE: Semaphore = Semaphore::const_new(1);

fn space(usage: SpaceUsage) -> Value {
    json!({"total_bytes": usage.total, "used_bytes": usage.used})
}

fn report() -> Result<Value> {
    let (pool, _) = handoff::host_data()?;
    let health = fvca_btrfs_boundary::mirror_health(&pool)?;
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
