use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use rustix::fs::OFlags;
use serde::{Deserialize, Serialize};

use crate::{Result, depot::METADATA_BYTES, invalid};

const METADATA: [&str; 5] = [
    "root.json",
    "timestamp.json",
    "snapshot.json",
    "targets.json",
    "latest_known_time.json",
];
const SAVED_BYTES: u64 = 16 * METADATA_BYTES;

pub fn open_regular(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY).bits() as i32)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("expected a regular file"));
    }
    Ok(file)
}

pub fn read(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let mut payload = Vec::new();
    open_regular(path)?
        .take(limit + 1)
        .read_to_end(&mut payload)?;
    if payload.is_empty() || payload.len() as u64 > limit {
        return Err(invalid("input exceeds its size bound or is empty"));
    }
    Ok(payload)
}

pub fn directory(path: &Path) -> io::Result<()> {
    let info = fs::symlink_metadata(path)?;
    if !info.is_dir()
        || info.uid() != rustix::process::geteuid().as_raw()
        || info.permissions().mode() & 0o7777 != 0o700
    {
        return Err(invalid(
            "release state directory must be owned by this account with mode 0700",
        ));
    }
    Ok(())
}

pub fn lock(path: &Path) -> io::Result<File> {
    directory(path)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY).bits() as i32)
        .open(path.join("intake.lock"))?;
    if !lock.metadata()?.is_file() {
        return Err(invalid("invalid release state lock"));
    }
    lock.try_lock().map_err(io::Error::other)?;
    Ok(lock)
}

pub fn staged(path: &Path) -> io::Result<()> {
    match DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => (),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error),
    }
    directory(path)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataState {
    bootstrap: String,
    documents: [Option<String>; METADATA.len()],
}

impl MetadataState {
    pub fn restore(
        state: &Path,
        work: &Path,
        bootstrap: &str,
        initial_root: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let saved: Self = match read(&state.join("trusted-tuf.json"), SAVED_BYTES) {
            Ok(data) => serde_json::from_slice(&data)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(initial_root),
            Err(error) => return Err(error.into()),
        };
        if saved.bootstrap != bootstrap {
            return Err(invalid("TUF bootstrap root differs from persistent release state").into());
        }
        for (name, data) in METADATA.into_iter().zip(&saved.documents) {
            if let Some(document) = data {
                if document.len() as u64 > METADATA_BYTES {
                    return Err(invalid("persisted TUF metadata exceeds its size bound").into());
                }
                fs::write(work.join(name), document)?;
            }
        }
        Ok(read(&work.join(METADATA[0]), METADATA_BYTES)?)
    }

    pub fn save(state: &Path, work: &Path, bootstrap: String) -> Result<()> {
        let mut documents = [const { None }; METADATA.len()];
        for (name, entry) in METADATA.into_iter().zip(&mut documents) {
            match read(&work.join(name), METADATA_BYTES) {
                Ok(bytes) => {
                    serde_json::from_slice::<serde::de::IgnoredAny>(&bytes)?;
                    *entry = Some(String::from_utf8(bytes)?);
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => (),
                Err(error) => return Err(error.into()),
            }
        }
        if documents[0].is_none() {
            return Err(invalid("trusted TUF root could not be persisted").into());
        }
        let mut record = tempfile::NamedTempFile::new_in(state)?;
        serde_json::to_writer(
            &mut record,
            &Self {
                bootstrap,
                documents,
            },
        )?;
        record.flush()?;
        if record.as_file().metadata()?.len() > SAVED_BYTES {
            return Err(invalid("serialized TUF state exceeds its bound").into());
        }
        record.as_file().sync_all()?;
        record.persist(state.join("trusted-tuf.json"))?;
        File::open(state)?.sync_all()?;
        Ok(())
    }
}
