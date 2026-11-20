use std::fs::File;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures_util::{StreamExt, TryStreamExt};
use reqwest::header::{ACCEPT_ENCODING, CONTENT_ENCODING};
use reqwest::{Certificate, Client, StatusCode};
use rustix::fs::{self, Mode, OFlags};
use serde::Deserialize;
use tokio::io::AsyncReadExt;
use tokio_util::io::ReaderStream;
use tough::{Transport, TransportError, TransportErrorKind, TransportStream};
use url::{Host, Url};

use crate::{Result, invalid, state};

pub const METADATA_BYTES: u64 = 1024 * 1024;
pub const CONFIG_BYTES: u64 = 64 * 1024;
pub enum EnrolledDepot {
    Local,
    Https(IpAddr),
}

impl EnrolledDepot {
    pub fn load(boot: &Path, name: &str) -> Result<Self> {
        let bytes = state::read(&boot.join(format!("{name}-depot")), 64)?;
        let selector = std::str::from_utf8(&bytes)?
            .strip_suffix('\n')
            .ok_or_else(|| invalid("invalid signed update depot selector"))?;
        if selector == "local" {
            return Ok(Self::Local);
        }
        let address: IpAddr = selector.parse()?;
        if address.is_unspecified() || address.is_multicast() {
            return Err(invalid("invalid signed update depot address").into());
        }
        Ok(Self::Https(address))
    }
}

#[derive(Deserialize)]
#[serde(tag = "transport", rename_all = "kebab-case", deny_unknown_fields)]
enum Config {
    Local {
        path: PathBuf,
    },
    Https {
        base_url: Url,
        ca_file: PathBuf,
        deadline_seconds: u64,
    },
}

#[derive(Clone, Debug)]
enum Backend {
    Local {
        metadata: Arc<File>,
        targets: Arc<File>,
    },
    Https {
        client: Client,
        deadline: Instant,
    },
}

#[derive(Clone, Debug)]
pub struct Depot {
    metadata: Url,
    targets: Url,
    max_target_bytes: u64,
    backend: Backend,
}

#[derive(Clone, Copy)]
struct Entry<'a> {
    name: &'a str,
    metadata: bool,
    limit: u64,
}

impl Depot {
    pub fn from_config(config: &[u8], max_target_bytes: u64) -> Result<Self> {
        Self::with_scope(config, max_target_bytes, None)
    }

    pub fn with_scope(
        config: &[u8],
        max_target_bytes: u64,
        scope: Option<(&EnrolledDepot, &str)>,
    ) -> Result<Self> {
        let config: Config = serde_json::from_slice(config)?;
        let (metadata, targets, backend) = match config {
            Config::Local { path } => {
                if !path.is_absolute() {
                    return Err(invalid("local depot requires an absolute path").into());
                }
                let expected = scope
                    .map(|(_, name)| Path::new("/run/fvca/host-data").join(name).join("depot"));
                if let Some((endpoint, _)) = scope
                    && (!matches!(endpoint, EnrolledDepot::Local)
                        || expected.as_ref() != Some(&path))
                {
                    return Err(
                        invalid("local depot differs from the signed update enrollment").into(),
                    );
                }
                let root = path.canonicalize()?;
                if expected.as_ref().is_some_and(|expected| expected != &root) {
                    return Err(invalid(
                        "local depot resolves outside the signed update enrollment",
                    )
                    .into());
                }
                let metadata = root.join("metadata");
                let targets = root.join("targets");
                let backend = Backend::Local {
                    metadata: open_directory(&metadata)?,
                    targets: open_directory(&targets)?,
                };
                (directory_url(&metadata)?, directory_url(&targets)?, backend)
            }
            Config::Https {
                base_url,
                ca_file,
                deadline_seconds,
            } => {
                if let Some((endpoint, name)) = scope {
                    let address = match base_url.host() {
                        Some(Host::Ipv4(ip)) => Some(IpAddr::V4(ip)),
                        Some(Host::Ipv6(ip)) => Some(IpAddr::V6(ip)),
                        _ => None,
                    };
                    if !matches!(endpoint, EnrolledDepot::Https(ip) if address == Some(*ip))
                        || ca_file != Path::new("/run/fvca").join(format!("{name}-ca.pem"))
                    {
                        return Err(invalid(
                            "HTTPS depot or CA differs from the signed update enrollment",
                        )
                        .into());
                    }
                    if address.is_some_and(|ip| !ip.is_loopback())
                        && base_url.port_or_known_default() != Some(443)
                    {
                        return Err(invalid(
                            "the enrolled remote HTTPS depot requires TCP port 443",
                        )
                        .into());
                    }
                }
                if base_url.scheme() != "https"
                    || base_url.host().is_none()
                    || !base_url.path().ends_with('/')
                    || !base_url.username().is_empty()
                    || base_url.password().is_some()
                    || base_url.query().is_some()
                    || base_url.fragment().is_some()
                    || !ca_file.is_absolute()
                    || !(1..=86_400).contains(&deadline_seconds)
                {
                    return Err(invalid("HTTPS depot requires an HTTPS directory URL, an absolute CA path and a bounded deadline").into());
                }
                let certificates =
                    Certificate::from_pem_bundle(&state::read(&ca_file, CONFIG_BYTES)?)?;
                if certificates.is_empty() {
                    return Err(invalid("HTTPS depot CA bundle contains no certificates").into());
                }
                let client = Client::builder()
                    .https_only(true)
                    .tls_certs_only(certificates)
                    .no_proxy()
                    .redirect(reqwest::redirect::Policy::none())
                    .retry(reqwest::retry::never())
                    .connect_timeout(Duration::from_secs(10))
                    .read_timeout(Duration::from_secs(30))
                    .build()?;
                let deadline = Instant::now() + Duration::from_secs(deadline_seconds);
                (
                    base_url.join("metadata/")?,
                    base_url.join("targets/")?,
                    Backend::Https { client, deadline },
                )
            }
        };
        Ok(Self {
            metadata,
            targets,
            max_target_bytes,
            backend,
        })
    }

    pub fn urls(&self) -> (Url, Url) {
        (self.metadata.clone(), self.targets.clone())
    }

    fn entry<'a>(&self, url: &'a Url) -> io::Result<Entry<'a>> {
        let (name, metadata, limit) =
            if let Some(name) = url.as_str().strip_prefix(self.metadata.as_str()) {
                (name, true, METADATA_BYTES)
            } else if let Some(name) = url.as_str().strip_prefix(self.targets.as_str()) {
                (name, false, self.max_target_bytes)
            } else {
                return Err(invalid(
                    "TUF file is outside the approved depot directories",
                ));
            };
        if name.is_empty()
            || matches!(name, "." | "..")
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".-_".contains(&byte))
        {
            return Err(invalid("invalid TUF depot filename"));
        }
        if metadata
            && name != "timestamp.json"
            && !name.split_once('.').is_some_and(|(version, suffix)| {
                version.parse::<u64>().is_ok_and(|version| version > 0)
                    && matches!(suffix, "root.json" | "snapshot.json" | "targets.json")
            })
        {
            return Err(invalid("expected top-level TUF metadata"));
        }
        Ok(Entry {
            name,
            metadata,
            limit,
        })
    }
}

fn open_directory(path: &Path) -> io::Result<Arc<File>> {
    let fd = fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    Ok(Arc::new(File::from(fd)))
}

fn directory_url(path: &Path) -> io::Result<Url> {
    Url::from_directory_path(path).map_err(|()| invalid("invalid TUF depot path"))
}

fn local_stream(directory: &File, entry: Entry<'_>, url: &Url) -> io::Result<TransportStream> {
    let file = File::from(fs::openat(
        directory,
        entry.name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > entry.limit {
        return Err(invalid("TUF depot entry is not a bounded regular file"));
    }
    let url = url.clone();
    let stream = ReaderStream::new(tokio::fs::File::from_std(file).take(entry.limit + 1));
    Ok(Box::pin(stream.map_err(move |error| {
        TransportError::new_with_cause(TransportErrorKind::Other, &url, error)
    })))
}

async fn https_stream(
    client: &Client,
    deadline: Instant,
    url: &Url,
    limit: u64,
) -> Result<TransportStream> {
    let timeout = deadline.saturating_duration_since(Instant::now());
    if timeout.is_zero() {
        return Err(
            io::Error::new(io::ErrorKind::TimedOut, "HTTPS depot deadline exceeded").into(),
        );
    }
    let response = client
        .get(url.clone())
        .header(ACCEPT_ENCODING, "identity")
        .timeout(timeout)
        .send()
        .await?;
    match response.status() {
        StatusCode::OK => (),
        StatusCode::NOT_FOUND => {
            return Err(io::Error::new(io::ErrorKind::NotFound, "HTTPS depot returned 404").into());
        }
        status => return Err(invalid(&format!("HTTPS depot returned {status}")).into()),
    }
    if response
        .headers()
        .get_all(CONTENT_ENCODING)
        .iter()
        .any(|value| value != "identity")
    {
        return Err(invalid("HTTPS depot returned an encoded body").into());
    }
    if response
        .content_length()
        .is_some_and(|length| length > limit)
    {
        return Err(invalid("HTTPS depot object exceeds its size bound").into());
    }
    let url = url.clone();
    let mut remaining = limit;
    let stream = response.bytes_stream().map(move |block| {
        let block = block.map_err(|error| {
            TransportError::new_with_cause(TransportErrorKind::Other, &url, error)
        })?;
        remaining = remaining.checked_sub(block.len() as u64).ok_or_else(|| {
            TransportError::new_with_cause(
                TransportErrorKind::Other,
                &url,
                invalid("HTTPS depot stream exceeds its size bound"),
            )
        })?;
        Ok(block)
    });
    Ok(Box::pin(stream))
}

#[async_trait]
impl Transport for Depot {
    async fn fetch(&self, url: Url) -> std::result::Result<TransportStream, TransportError> {
        let result: Result<_> = match self.entry(&url) {
            Ok(entry) => match &self.backend {
                Backend::Local { metadata, targets } => {
                    local_stream(if entry.metadata { metadata } else { targets }, entry, &url)
                        .map_err(Into::into)
                }
                Backend::Https { client, deadline } => {
                    https_stream(client, *deadline, &url, entry.limit).await
                }
            },
            Err(error) => Err(error.into()),
        };
        // Tough's root lookup distinguishes a missing root from a broken stream.
        Ok(match result {
            Ok(stream) => stream,
            Err(error) => {
                let kind = if error
                    .downcast_ref::<io::Error>()
                    .is_some_and(|error| error.kind() == io::ErrorKind::NotFound)
                {
                    TransportErrorKind::FileNotFound
                } else {
                    TransportErrorKind::Other
                };
                let failed = TransportError::new_with_cause(kind, &url, error);
                Box::pin(futures_util::stream::iter([Err(failed)]))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduled_discovery_requires_the_enrolled_transport_and_address() {
        let local = br#"{"transport":"local","path":"/different-depot"}"#;
        let wrong_https = br#"{"transport":"https","base_url":"https://192.0.2.2/",
            "ca_file":"/run/fvca/os-update-ca.pem","deadline_seconds":60}"#;
        let wrong_ca = br#"{"transport":"https","base_url":"https://192.0.2.1/",
            "ca_file":"/different-ca.pem","deadline_seconds":60}"#;
        let https = EnrolledDepot::Https(IpAddr::from([192, 0, 2, 1]));
        for (config, scope) in [
            (local.as_slice(), &EnrolledDepot::Local),
            (wrong_https.as_slice(), &EnrolledDepot::Local),
            (wrong_https.as_slice(), &https),
            (wrong_ca.as_slice(), &https),
        ] {
            let error = Depot::with_scope(config, 1024, Some((scope, "os-update"))).unwrap_err();
            assert!(error.to_string().contains("signed update enrollment"));
        }
    }
}
