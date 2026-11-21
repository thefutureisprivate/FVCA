//! Shared bounded TUF intake for the role-specific release clients.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use futures_util::{TryStreamExt, pin_mut};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tough::schema::{Metafile, RoleType, Root, Signed, key::Key};
use tough::{Limits, Repository, RepositoryLoader, TargetName};

use crate::depot::{Depot, METADATA_BYTES};
use crate::state::{self, MetadataState};
use crate::{Result, invalid};

fn validate_root(bytes: &[u8], limits: Limits) -> Result<()> {
    let root: Signed<Root> = serde_json::from_slice(bytes)?;
    if !root.signed.consistent_snapshot
        || root
            .signed
            .version
            .get()
            .checked_add(limits.max_root_updates)
            .is_none()
    {
        return Err(invalid("TUF root requires consistent snapshots and a bounded version").into());
    }
    root.signed.verify_role(&root)?;
    let mut public_keys = HashSet::new();
    for name in [
        RoleType::Root,
        RoleType::Targets,
        RoleType::Snapshot,
        RoleType::Timestamp,
    ] {
        let role = root
            .signed
            .roles
            .get(&name)
            .ok_or_else(|| invalid("missing TUF role"))?;
        if role.threshold.get() > role.keyids.len() as u64 {
            return Err(invalid("unreachable TUF role threshold").into());
        }
        for key in &role.keyids {
            let Some(Key::Ed25519 { keyval, .. }) = root.signed.keys.get(key) else {
                return Err(invalid("TUF role requires Ed25519 public keys").into());
            };
            let public = keyval.public.as_ref();
            if public.len() != 32 || !public_keys.insert(public) {
                return Err(invalid("TUF keys must be distinct across all release roles").into());
            }
        }
    }
    Ok(())
}

fn linked_metadata(entry: Option<&Metafile>) -> bool {
    entry.is_some_and(|entry| {
        entry
            .length
            .is_some_and(|len| (1..=METADATA_BYTES).contains(&len))
            && entry
                .hashes
                .as_ref()
                .is_some_and(|hashes| hashes.sha256.as_ref().len() == 32)
    })
}

fn repository_profile(repo: &Repository) -> io::Result<()> {
    let timestamp = &repo.timestamp().signed;
    let snapshot = &repo.snapshot().signed;
    if !linked_metadata(timestamp.meta.get("snapshot.json"))
        || !linked_metadata(snapshot.meta.get("targets.json"))
        || snapshot.meta.len() != 1
        || repo.targets().signed.delegations.is_some()
    {
        return Err(invalid(
            "TUF release profile requires hash-bound top-level metadata",
        ));
    }
    let now = jiff::Timestamp::now().as_second();
    let timestamp_validity = timestamp.expires.as_second() - now;
    let snapshot_validity = snapshot.expires.as_second() - now;
    if !(0..=86_400).contains(&timestamp_validity) || !(0..=604_800).contains(&snapshot_validity) {
        return Err(invalid(
            "online TUF metadata expires outside the permitted window",
        ));
    }
    Ok(())
}

pub fn check_target(repo: &Repository, name: &TargetName, limit: u64, sha256: &str) -> Result<u64> {
    let target = repo
        .targets()
        .signed
        .targets
        .get(name)
        .ok_or_else(|| invalid("approved TUF target is missing"))?;
    if !(1..=limit).contains(&target.length)
        || target.hashes.sha256.as_ref() != hex::decode(sha256)?
    {
        return Err(
            invalid("TUF target digest or length differs from the approved release").into(),
        );
    }
    Ok(target.length)
}

pub async fn load_repository(
    depot: Depot,
    state_dir: &Path,
    initial_root: Vec<u8>,
    work: &Path,
) -> Result<Repository> {
    let bootstrap = hex::encode(Sha256::digest(&initial_root));
    let root = MetadataState::restore(state_dir, work, &bootstrap, initial_root)?;
    let limits = Limits {
        max_root_size: METADATA_BYTES,
        max_targets_size: METADATA_BYTES,
        max_timestamp_size: METADATA_BYTES,
        max_snapshot_size: METADATA_BYTES,
        ..Limits::default()
    };
    validate_root(&root, limits)?;
    fs::write(work.join("root.json"), &root)?;
    let (metadata, targets) = depot.urls();
    let loaded = RepositoryLoader::new(&root, metadata, targets)
        .transport(depot)
        .limits(limits)
        .datastore(work)
        .load()
        .await;
    // Recover the library's verified checkpoints, including a valid root rotation followed by a missing target index.
    let advanced_root = state::read(&work.join("root.json"), METADATA_BYTES)?;
    validate_root(&advanced_root, limits)?;
    MetadataState::save(state_dir, work, bootstrap)?;
    let repo = loaded?;
    repository_profile(&repo)?;
    Ok(repo)
}

pub fn output_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(path)
}

pub async fn download(
    repo: &Repository,
    target: &TargetName,
    path: &Path,
    length: u64,
) -> Result<()> {
    let stream = repo
        .read_target(target)
        .await?
        .ok_or_else(|| invalid("authorized TUF member disappeared"))?;
    pin_mut!(stream);
    let mut file = tokio::fs::File::from_std(output_file(path)?);
    let mut remaining = length;
    while let Some(chunk) = stream.try_next().await? {
        remaining = remaining
            .checked_sub(chunk.len() as u64)
            .ok_or_else(|| invalid("TUF member exceeds its exact length"))?;
        file.write_all(&chunk).await?;
    }
    if remaining != 0 {
        return Err(invalid("TUF member is shorter than its exact length").into());
    }
    file.flush().await?;
    file.sync_all().await?;
    Ok(())
}
