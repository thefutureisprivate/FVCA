//! Expire only finalized, unpinned snapshots under boot-authorized policy.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use fvca_initrd_bootstrap::retention_policy::{self, Policy};

use super::{Consistency, backup, btrfs, invalid, lease, live, optional_record, private_directory,
            publish, recorded_capture, restore, snapshot_at, uuid};
use crate::{CAPTURE_LOCK, POOL, verify_pool};

const SETS: &str = "/run/fvca/host-data/captures/sets";

struct Capture {
    id: String,
    path: PathBuf,
    complete: Option<Complete>,
}

struct Complete {
    captured: u64,
    sequence: u64,
    volume: String,
    digest: String,
    consistency: Consistency,
    pending_backup: bool,
    retiring: bool,
    expired: bool,
    present: bool,
}

impl Complete {
    fn expiry_record(&self, id: &str) -> String {
        format!("FVCA-LOCAL-CAPTURE-EXPIRED-1\ncapture={id}\nsnapshot_uuid={}\nsnapshot_id={}\ndisk_sha256={}\n",
                self.volume, self.sequence, self.digest)
    }

    fn load(path: &Path, id: &str, fsid: &str) -> io::Result<Option<Self>> {
        let Some(manifest) = optional_record(&path.join("manifest"))? else { return Ok(None); };
        let record = recorded_capture(path, id, fsid, &manifest)?;
        let mut pending_backup = false;
        for entry in fs::read_dir(path)? {
            let name = entry?.file_name();
            if name.to_str().is_some_and(|name| name.starts_with("backup-pending-")) {
                pending_backup = true;
                break;
            }
        }
        let intent = optional_record(&path.join("expire-intent"))?;
        let expired = optional_record(&path.join("expired"))?;
        let present = path.join("snapshot").try_exists()?;
        let complete = Self {
            captured: record.plan.captured, sequence: record.sequence, volume: record.volume.to_owned(),
            digest: record.digest.to_owned(), consistency: record.consistency, pending_backup,
            retiring: intent.is_some(), expired: expired.is_some(), present,
        };
        let expected = complete.expiry_record(id);
        if intent.as_ref().is_some_and(|value| *value != expected)
            || expired.as_ref().is_some_and(|value| Some(value) != intent.as_ref() || present)
            || (!present && intent.is_none())
        {
            return Err(invalid("local capture state does not match its expiry journal"));
        }
        if present {
            let (snapshot, _) = snapshot_at(path, record.consistency, &record.plan)?;
            if snapshot.id != record.sequence || snapshot.uuid != complete.volume {
                return Err(invalid("local snapshot differs from the verified capture inventory"));
            }
        }
        Ok(Some(complete))
    }
}

fn catalog(fsid: &str, selected: Option<&str>) -> io::Result<Vec<Capture>> {
    let base = Path::new(SETS);
    if !base.try_exists()? {
        return Ok(Vec::new());
    }
    private_directory(Path::new(POOL).join("captures").as_path())?;
    private_directory(base)?;
    let mut captures = Vec::new();
    for entry in fs::read_dir(base)? {
        let entry = entry?;
        let name = entry.file_name().into_string().map_err(|_| invalid("invalid capture directory name"))?;
        uuid(&name)?;
        if selected.is_some_and(|selected| selected != name) {
            continue;
        }
        let path = entry.path();
        private_directory(&path)?;
        let complete = Complete::load(&path, &name, fsid)?;
        captures.push(Capture { id: name, path, complete });
    }
    captures.sort_by(|a, b| {
        let order = |capture: &Capture| capture.complete.as_ref().map(|record| (record.captured, record.sequence));
        order(b).cmp(&order(a)).then_with(|| a.id.cmp(&b.id))
    });
    Ok(captures)
}

pub(crate) fn inspect(selected: Option<&str>) -> io::Result<()> {
    if let Some(id) = selected {
        uuid(id)?;
    }
    let _catalog = lease(Path::new(CAPTURE_LOCK))?;
    let fsid = btrfs::filesystem_uuid(&verify_pool()?)?;
    let captures = catalog(&fsid, selected)?;
    if selected.is_some() && captures.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "unknown local capture"));
    }
    for capture in captures {
        let id = &capture.id;
        if let Some(record) = capture.complete {
            let state = if record.expired { "expired" } else if record.retiring { "expiry-pending" } else { "complete" };
            println!("FVCA_LOCAL_CAPTURE {id} state={state} consistency={} captured={} snapshot={} disk_sha256={} backup_pending={}",
                     record.consistency.name(), record.captured, record.volume, record.digest, record.pending_backup);
        } else {
            println!("FVCA_LOCAL_CAPTURE {id} state=pending");
        }
    }
    Ok(())
}

fn finish_expiry(pool: &File, capture: &Capture, complete: &Complete) -> io::Result<()> {
    if capture.path.join("snapshot").try_exists()? {
        return Err(invalid("the retired snapshot is still visible"));
    }
    btrfs::sync(pool)?;
    publish(&capture.path, "expired", &complete.expiry_record(&capture.id))?;
    println!("FVCA_LOCAL_CAPTURE_EXPIRED {} {}", capture.id, complete.volume);
    Ok(())
}

fn expire(pool: &File, fsid: &str, capture: &Capture, policy: &Policy<'_>) -> io::Result<bool> {
    let _pin = match lease(&capture.path.join("lock")) {
        Ok(pin) => pin,
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
        Err(error) => return Err(error),
    };
    let record = Complete::load(&capture.path, &capture.id, fsid)?
        .ok_or_else(|| invalid("the capture is no longer finalized"))?;
    if record.pending_backup || record.expired || !record.present {
        return Ok(false);
    }
    let receipt = capture.path.join(format!("backup-{}", policy.repository));
    let Some(receipt) = optional_record(&receipt)? else { return Ok(false); };
    backup::received_snapshot(&receipt, &capture.id, &record.digest, policy.repository)?;
    let dir = private_directory(&capture.path)?;
    if btrfs::filesystem_uuid(&dir)? != fsid {
        return Err(invalid("cannot expire outside the authorized Btrfs pool"));
    }
    publish(&capture.path, "expire-intent", &record.expiry_record(&capture.id))?;
    btrfs::remove_capture_snapshot(&dir)?;
    finish_expiry(pool, capture, &record)?;
    Ok(true)
}

pub(crate) fn maintain(selected: Option<&str>) -> io::Result<()> {
    if let Some(id) = selected {
        uuid(id)?;
    }
    let text = fs::read_to_string(retention_policy::POLICY)?;
    let policy = retention_policy::parse(&text)?;
    let _backup = lease(Path::new(backup::BACKUP_LOCK))?;
    let _restore = lease(Path::new(restore::RESTORE_LOCK))?;
    let _catalog = lease(Path::new(CAPTURE_LOCK))?;
    live::require_idle()?;
    restore::require_idle()?;
    let pins = restore::pinned_captures()?;
    let pool = verify_pool()?;
    let fsid = btrfs::filesystem_uuid(&pool)?;
    let captures = catalog(&fsid, None)?;
    let mut rank = Vec::new();
    for capture in &captures {
        let Some(record) = &capture.complete else { continue; };
        if !record.present {
            if selected.is_none_or(|selected| selected == capture.id) {
                if record.expired {
                    if selected.is_some() {
                        println!("FVCA_LOCAL_CAPTURE_EXPIRED {} {}", capture.id, record.volume);
                        return Ok(());
                    }
                } else {
                    let _pin = lease(&capture.path.join("lock"))?;
                    finish_expiry(&pool, capture, record)?;
                    if selected.is_some() { return Ok(()); }
                }
            }
        } else {
            rank.push((capture, record));
        }
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(io::Error::other)?.as_secs();
    let space = btrfs::headroom(&pool)?;
    let pressure = !space.affords(policy.min_data_bytes, policy.min_metadata_bytes);
    let minimum: BTreeSet<_> = rank.iter().filter(|(_, record)| !record.retiring).take(policy.keep_min)
        .map(|(capture, _)| capture.id.as_str()).collect();
    let mut remaining = rank.len();
    let mut removed = 0;
    for (capture, record) in rank.into_iter().rev() {
        if selected.is_some_and(|selected| selected != capture.id) || minimum.contains(capture.id.as_str())
            || record.pending_backup || policy.protected.contains(capture.id.as_str()) || pins.contains(&capture.id)
        {
            continue;
        }
        let Some(age) = now.checked_sub(record.captured) else { continue; };
        // Pressure alone permits one expiry per pass. Btrfs reclaims shared
        // extents asynchronously, so the next pass measures actual free space.
        if (record.retiring || age >= policy.max_age_seconds || remaining > policy.keep_max || (pressure && removed == 0))
            && expire(&pool, &fsid, capture, &policy)?
        {
            remaining -= 1;
            removed += 1;
        }
    }
    if selected.is_some() && removed == 0 {
        return Err(invalid("the requested capture is protected, pinned, or outside expiry policy"));
    }
    println!("FVCA_LOCAL_RETENTION remaining={remaining} expired={removed} pressure={pressure} data_free={} metadata_free={} system_free={} mirror_unallocated={}",
             space.data, space.metadata, space.system, space.unallocated);
    Ok(())
}
