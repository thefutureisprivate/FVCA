//! Bounded, read-only inventory of the registered Guest's Host recovery points.

use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;

use fvca_btrfs_boundary as btrfs;
use fvca_trial_authorization::capture::{Manifest, RECORD_BYTES, expiry_record};
use rustix::fs::{self, Dir, Mode, OFlags};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};

use super::protocol::{Refusal, current_time};
use super::storage_health::observe;
use crate::{Result, handoff, invalid, valid_uuid};

const PAGE: usize = 8;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Cursor {
    filesystem_uuid: String,
    directory_inode: u64,
    offset: i64,
}

#[derive(Serialize)]
pub(super) struct Capture {
    capture_id: String,
    state: State,
    finalized: Option<Finalized>,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
enum State {
    Pending,
    Complete,
    ExpiryPending,
    Expired,
}

#[derive(Serialize)]
struct Finalized {
    snapshot_uuid: String,
    snapshot_id: u64,
    disk_sha256: String,
    consistency: &'static str,
    captured_at: u64,
    age_seconds: Option<u64>,
}

fn child(parent: &File, path: &str, flags: OFlags) -> io::Result<Option<File>> {
    if path.is_empty() || matches!(path, "." | "..") || path.contains('/') {
        return Err(invalid("expected a single capture path component"));
    }
    match fs::openat(
        parent,
        path,
        flags | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(file) => {
            let file = File::from(file);
            if handoff::mount_id(&file)? != handoff::mount_id(parent)? {
                return Err(invalid("capture entry is outside the selected Host mount"));
            }
            Ok(Some(file))
        }
        Err(Errno::NOENT) => Ok(None),
        Err(error) => Err(io::Error::new(
            io::Error::from(error).kind(),
            format!("could not open capture entry {path}: {error}"),
        )),
    }
}

fn directory(parent: &File, path: &str) -> io::Result<Option<File>> {
    let Some(file) = child(parent, path, OFlags::RDONLY | OFlags::DIRECTORY)? else {
        return Ok(None);
    };
    let meta = file.metadata()?;
    if meta.uid() != 0 || meta.gid() != 0 || meta.mode() & 0o7777 != 0o700 {
        return Err(invalid(&format!(
            "capture directory {path} must be private and owned by root"
        )));
    }
    Ok(Some(file))
}

fn record(dir: &File, name: &str) -> io::Result<Option<String>> {
    let Some(file) = child(
        dir,
        name,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY,
    )?
    else {
        return Ok(None);
    };
    handoff::private_file(&file)?;
    let mut text = String::new();
    file.take(RECORD_BYTES + 1).read_to_string(&mut text)?;
    if text.len() as u64 > RECORD_BYTES {
        return Err(invalid("capture record exceeds its size limit"));
    }
    Ok(Some(text))
}

struct Catalog {
    root: File,
    filesystem_uuid: String,
    observed_at: u64,
}

impl Catalog {
    fn open() -> Result<Option<Self>> {
        let (pool, _) = handoff::host_data()?;
        let Some(captures) = directory(&pool, "captures")? else {
            return Ok(None);
        };
        let Some(root) = directory(&captures, "sets")? else {
            return Ok(None);
        };
        Ok(Some(Self {
            root,
            filesystem_uuid: btrfs::filesystem_uuid(&pool)?,
            observed_at: current_time()?,
        }))
    }

    fn capture(&self, id: String) -> Result<Option<Capture>> {
        let Some(dir) = directory(&self.root, &id)? else {
            return Ok(None);
        };
        let Some(text) = record(&dir, "manifest")? else {
            return Ok(Some(Capture {
                capture_id: id,
                state: State::Pending,
                finalized: None,
            }));
        };
        let manifest = Manifest::parse(&text, &id, Some(&self.filesystem_uuid))?;
        manifest.verify_sidecars(|name| {
            record(&dir, name)?.ok_or_else(|| invalid("missing capture sidecar"))
        })?;
        // The expiry intent is installed before deletion. Inspect it after opening the
        // snapshot so a concurrent expiry cannot result in an advertised recovery point.
        let snapshot = directory(&dir, "snapshot")?.map(|file| btrfs::subvolume(&file));
        let expired = record(&dir, "expired")?;
        let intent = record(&dir, "expire-intent")?;
        let (state, age_seconds) = if let Some(intent) = intent {
            let expected = expiry_record(&id, manifest.volume, manifest.sequence, manifest.digest);
            if intent != expected || expired.as_ref().is_some_and(|entry| entry != &expected) {
                return Err(invalid("capture expiry records do not match its manifest").into());
            }
            if expired.is_some() {
                if directory(&dir, "snapshot")?.is_some() {
                    return Err(invalid("an expired capture still has a snapshot").into());
                }
                (State::Expired, None)
            } else {
                (State::ExpiryPending, None)
            }
        } else {
            let snapshot =
                snapshot.ok_or_else(|| invalid("finalized capture has no snapshot"))??;
            if expired.is_some()
                || !snapshot.read_only
                || snapshot.uuid != manifest.volume
                || snapshot.id != manifest.sequence
                || snapshot.parent_uuid != manifest.plan.source
            {
                return Err(invalid("local snapshot differs from its finalized manifest").into());
            }
            let age = self
                .observed_at
                .checked_sub(manifest.plan.captured)
                .ok_or_else(|| invalid("the Host clock precedes the local capture"))?;
            (State::Complete, Some(age))
        };
        Ok(Some(Capture {
            capture_id: id,
            state,
            finalized: Some(Finalized {
                snapshot_uuid: manifest.volume.to_owned(),
                snapshot_id: manifest.sequence,
                disk_sha256: manifest.digest.to_owned(),
                consistency: manifest.consistency.name(),
                captured_at: manifest.plan.captured,
                age_seconds,
            }),
        }))
    }

    fn page(&self, mut entries: Dir) -> Result<(Vec<Capture>, Option<Cursor>)> {
        let mut captures = Vec::with_capacity(PAGE);
        let mut last = None;
        let directory_inode = self.root.metadata()?.ino();
        for entry in &mut entries {
            let entry = entry?;
            let name = entry.file_name().to_str()?;
            if matches!(name, "." | "..") {
                continue;
            }
            if captures.len() == PAGE {
                return Ok((captures, last));
            }
            if !valid_uuid(name) {
                return Err(invalid("unexpected capture directory name").into());
            }
            let capture = self
                .capture(name.to_owned())?
                .ok_or_else(|| invalid("capture directory disappeared"))?;
            captures.push(capture);
            last = Some(Cursor {
                filesystem_uuid: self.filesystem_uuid.clone(),
                directory_inode,
                offset: entry.offset(),
            });
        }
        Ok((captures, None))
    }
}

type Page = (Vec<Capture>, Option<Cursor>);

async fn query<T: Send + 'static>(
    read: impl FnOnce() -> Result<T> + Send + 'static,
) -> std::result::Result<T, Refusal> {
    observe(
        move || read().inspect_err(|error| eprintln!("FVCA_LOCAL_CAPTURE_UNAVAILABLE {error}")),
        Refusal::HostCaptureCatalogUnavailable,
    )
    .await
}

pub(super) async fn list(after: Option<Cursor>) -> std::result::Result<Page, Refusal> {
    query(move || {
        let Some(catalog) = Catalog::open()? else {
            return Ok(if after.is_some() {
                Err(Refusal::InvalidHostCaptureCursor)
            } else {
                Ok((Vec::new(), None))
            });
        };
        let mut entries = Dir::read_from(&catalog.root)?;
        if let Some(cursor) = after {
            if cursor.filesystem_uuid != catalog.filesystem_uuid
                || cursor.directory_inode != catalog.root.metadata()?.ino()
                || cursor.offset < 2
            {
                return Ok(Err(Refusal::InvalidHostCaptureCursor));
            }
            entries.seek(cursor.offset)?;
        }
        Ok(Ok(catalog.page(entries)?))
    })
    .await?
}

pub(super) async fn inspect(id: String) -> std::result::Result<Capture, Refusal> {
    if !valid_uuid(&id) {
        return Err(Refusal::UnknownHostCapture);
    }
    query(move || match Catalog::open()? {
        Some(catalog) => catalog.capture(id),
        None => Ok(None),
    })
    .await?
    .ok_or(Refusal::UnknownHostCapture)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::management::protocol::RESPONSE_BYTES;

    #[test]
    fn a_full_capture_page_fits_the_management_frame() -> Result<()> {
        let uuid = "12345678-1234-1234-1234-123456789abc";
        let captures: Vec<_> = (0..PAGE)
            .map(|_| Capture {
                capture_id: uuid.to_owned(),
                state: State::Complete,
                finalized: Some(Finalized {
                    snapshot_uuid: uuid.to_owned(),
                    snapshot_id: u64::MAX,
                    disk_sha256: "a".repeat(64),
                    consistency: "filesystem-consistent",
                    captured_at: u64::MAX,
                    age_seconds: Some(u64::MAX),
                }),
            })
            .collect();
        let response = super::super::Response {
            schema: "fvca-management-response-v1",
            nonce: "0123456789abcdef0123456789abcdef",
            host: uuid,
            guest: uuid,
            outcome: super::super::Outcome::HostLocalCaptures {
                captures,
                next: Some(Cursor {
                    filesystem_uuid: uuid.to_owned(),
                    directory_inode: u64::MAX,
                    offset: i64::MAX,
                }),
            },
        };
        assert!(serde_json::to_vec(&response)?.len() <= RESPONSE_BYTES);
        Ok(())
    }
}
