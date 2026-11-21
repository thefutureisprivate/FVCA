//! Delegate one authenticated read to the confined firmware observer.

use std::io::Write;
use std::os::unix::net::UnixStream as BlockingStream;
use std::path::Path;
use std::time::Duration;

use rustix::net::sockopt::socket_peercred;
use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;

use super::listener;
use crate::{Result, firmware::StatusSnapshot, invalid};

const SOCKET: &str = "/run/fvca-firmware-status/status.sock";
const STATUS_BYTES: u64 = 2048;

pub(super) async fn request() -> Result<StatusSnapshot> {
    let stream = UnixStream::connect(SOCKET).await?;
    if stream.peer_cred()?.uid() != 0 {
        return Err(invalid("invalid firmware observer socket owner").into());
    }
    let mut bytes = Vec::new();
    stream
        .take(STATUS_BYTES + 1)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() as u64 > STATUS_BYTES {
        return Err(invalid("firmware status exceeds its limit").into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

pub(crate) fn serve() -> Result<()> {
    listener::require_context("fvca_firmware_observer_t")?;
    let mut stream = BlockingStream::from(listener::take_connected("firmware-status")?);
    let peer = socket_peercred(&stream)?;
    if !peer.uid.is_root()
        || peer.gid.as_raw() != 0
        || stream.local_addr()?.as_pathname() != Some(Path::new(SOCKET))
    {
        return Err(invalid("invalid local firmware status connection").into());
    }
    stream.set_write_timeout(Some(Duration::from_secs(1)))?;
    let bytes = serde_json::to_vec(&StatusSnapshot::read()?)?;
    if bytes.len() as u64 > STATUS_BYTES {
        return Err(invalid("firmware status exceeds its limit").into());
    }
    stream.write_all(&bytes)?;
    Ok(())
}
