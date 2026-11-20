use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use futures_util::TryStreamExt;
use rustix::fs::{self, Mode, OFlags};
use tokio::io::AsyncReadExt;
use tokio_util::io::ReaderStream;
use tough::{Transport, TransportError, TransportErrorKind, TransportStream};
use url::Url;

pub const METADATA_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug)]
struct Directory {
    path: PathBuf,
    file: Arc<File>,
}

impl Directory {
    fn open(path: PathBuf) -> io::Result<Self> {
        let file = fs::open(
            &path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        Ok(Self {
            path,
            file: Arc::new(File::from(file)),
        })
    }

    fn url(&self) -> io::Result<Url> {
        Url::from_directory_path(&self.path).map_err(|()| crate::invalid("invalid TUF depot path"))
    }
}

#[derive(Clone, Debug)]
pub struct Depot {
    metadata: Directory,
    targets: Directory,
    max_target_bytes: u64,
}

impl Depot {
    pub fn open(path: &Path, max_target_bytes: u64) -> io::Result<Self> {
        let root = path.canonicalize()?;
        Ok(Self {
            metadata: Directory::open(root.join("metadata"))?,
            targets: Directory::open(root.join("targets"))?,
            max_target_bytes,
        })
    }

    pub fn urls(&self) -> io::Result<(Url, Url)> {
        Ok((self.metadata.url()?, self.targets.url()?))
    }

    fn open_file(&self, url: &Url) -> io::Result<(File, u64)> {
        let path = url
            .to_file_path()
            .map_err(|()| crate::invalid("TUF depot accepts only local files"))?;
        let (directory, limit) = match path.parent() {
            Some(parent) if parent == self.metadata.path => (&self.metadata, METADATA_BYTES),
            Some(parent) if parent == self.targets.path => (&self.targets, self.max_target_bytes),
            _ => {
                return Err(crate::invalid(
                    "TUF file is outside the approved depot directories",
                ));
            }
        };
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| {
                name.bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b".-_".contains(&byte))
            })
            .ok_or_else(|| crate::invalid("invalid TUF depot filename"))?;
        if directory.path == self.metadata.path
            && name != "timestamp.json"
            && !name.split_once('.').is_some_and(|(version, suffix)| {
                version.parse::<u64>().is_ok_and(|version| version > 0)
                    && matches!(suffix, "root.json" | "snapshot.json" | "targets.json")
            })
        {
            return Err(crate::invalid("expected top-level TUF metadata"));
        }
        let file = File::from(fs::openat(
            directory.file.as_ref(),
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > limit {
            return Err(crate::invalid(
                "TUF depot entry is not a bounded regular file",
            ));
        }
        Ok((file, limit))
    }
}

#[async_trait]
impl Transport for Depot {
    async fn fetch(&self, url: Url) -> Result<TransportStream, TransportError> {
        let (file, limit) = match self.open_file(&url) {
            Ok(opened) => opened,
            Err(error) => {
                let kind = if error.kind() == io::ErrorKind::NotFound {
                    TransportErrorKind::FileNotFound
                } else {
                    TransportErrorKind::Other
                };
                // Tough's root lookup distinguishes a missing root from a broken stream.
                let failed = TransportError::new_with_cause(kind, &url, error);
                return Ok(Box::pin(futures_util::stream::iter([Err(failed)])));
            }
        };
        let stream =
            ReaderStream::new(tokio::fs::File::from_std(file).take(limit.saturating_add(1)));
        Ok(Box::pin(stream.map_err(move |error| {
            TransportError::new_with_cause(TransportErrorKind::Other, &url, error)
        })))
    }
}
