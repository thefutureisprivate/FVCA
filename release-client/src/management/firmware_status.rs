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
    let stream = connect(SOCKET).await?;
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
    let mut stream = accept("firmware-status", SOCKET)?;
    stream.set_write_timeout(Some(Duration::from_secs(1)))?;
    let bytes = serde_json::to_vec(&StatusSnapshot::read()?)?;
    if bytes.len() as u64 > STATUS_BYTES {
        return Err(invalid("firmware status exceeds its limit").into());
    }
    stream.write_all(&bytes)?;
    Ok(())
}

pub(super) async fn connect(socket: &str) -> Result<UnixStream> {
    let stream = UnixStream::connect(socket).await?;
    if stream.peer_cred()?.uid() != 0 {
        return Err(invalid("invalid firmware observer socket owner").into());
    }
    Ok(stream)
}

pub(super) fn accept(name: &str, socket: &str) -> Result<BlockingStream> {
    let stream = BlockingStream::from(listener::take_connected(name)?);
    let peer = socket_peercred(&stream)?;
    if !peer.uid.is_root()
        || peer.gid.as_raw() != 0
        || stream.local_addr()?.as_pathname() != Some(Path::new(socket))
    {
        return Err(invalid("invalid local firmware observation connection").into());
    }
    Ok(stream)
}
