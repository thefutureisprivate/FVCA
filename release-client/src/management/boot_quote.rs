//! Delegate one authenticated challenge to the confined TPM collector.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream as BlockingStream;
use std::path::Path;
use std::time::Duration;

use rustix::net::sockopt::socket_peercred;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use super::listener;
use crate::{Result, attestation, invalid};

const SOCKET: &str = "/run/fvca-attestation/quote.sock";
const EVIDENCE_BYTES: u64 = 2048;

pub(super) async fn request(challenge: &[u8; 32]) -> Result<attestation::Evidence> {
    let mut stream = UnixStream::connect(SOCKET).await?;
    if stream.peer_cred()?.uid() != 0 {
        return Err(invalid("invalid boot quote socket owner").into());
    }
    stream.write_all(challenge).await?;
    stream.shutdown().await?;
    let mut evidence = Vec::new();
    stream
        .take(EVIDENCE_BYTES + 1)
        .read_to_end(&mut evidence)
        .await?;
    if evidence.len() as u64 > EVIDENCE_BYTES {
        return Err(invalid("boot quote evidence exceeds its limit").into());
    }
    Ok(serde_json::from_slice(&evidence)?)
}

pub(crate) fn serve() -> Result<()> {
    listener::require_context("fvca_attestation_t")?;
    let mut stream = BlockingStream::from(listener::take_connected("boot-quote")?);
    let peer = socket_peercred(&stream)?;
    if !peer.uid.is_root()
        || peer.gid.as_raw() != 0
        || stream.local_addr()?.as_pathname() != Some(Path::new(SOCKET))
    {
        return Err(invalid("invalid local boot quote connection").into());
    }
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
    let mut challenge = [0; 32];
    stream.read_exact(&mut challenge)?;
    if stream.read(&mut [0])? != 0 {
        return Err(invalid("expected exactly one fixed-size boot challenge").into());
    }
    let evidence = attestation::quote(&challenge)?;
    stream.write_all(&serde_json::to_vec(&evidence)?)?;
    Ok(())
}
