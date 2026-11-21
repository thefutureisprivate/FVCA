//! Pass a bounded device cursor to the read-only inventory account.

use std::io::{Read, Write};
use std::time::Duration;

use rustix::process::{getegid, geteuid};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{firmware_status, listener};
use crate::{
    Result,
    firmware::{InventoryCursor, InventoryReply, READER_UID, inventory_page},
    invalid,
};

const SOCKET: &str = "/run/fvca-firmware-status/inventory.sock";
const CURSOR_BYTES: u64 = 160;
const PAGE_BYTES: u64 = 3584;

pub(super) async fn request(after: Option<&InventoryCursor>) -> Result<InventoryReply> {
    let mut stream = firmware_status::connect(SOCKET).await?;
    stream.write_all(&serde_json::to_vec(&after)?).await?;
    stream.shutdown().await?;
    let mut bytes = Vec::new();
    stream.take(PAGE_BYTES + 1).read_to_end(&mut bytes).await?;
    if bytes.len() as u64 > PAGE_BYTES {
        return Err(invalid("firmware inventory page exceeds its limit").into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

pub(crate) fn serve() -> Result<()> {
    listener::require_context("fvca_firmware_reader_t")?;
    if geteuid().as_raw() != READER_UID || getegid().as_raw() != READER_UID {
        return Err(invalid("invalid firmware inventory reader identity").into());
    }
    let mut stream = firmware_status::accept("firmware-inventory", SOCKET)?;
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
    stream.set_write_timeout(Some(Duration::from_secs(1)))?;
    let mut bytes = Vec::new();
    (&stream).take(CURSOR_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > CURSOR_BYTES {
        return Err(invalid("firmware inventory cursor exceeds its limit").into());
    }
    let after: Option<InventoryCursor> = serde_json::from_slice(&bytes)?;
    if after.as_ref().is_some_and(|cursor| !cursor.valid()) {
        return Err(invalid("invalid firmware inventory cursor").into());
    }
    let reply = serde_json::to_vec(&inventory_page(after.as_ref())?)?;
    if reply.len() as u64 > PAGE_BYTES {
        return Err(invalid("firmware inventory page exceeds its limit").into());
    }
    stream.write_all(&reply)?;
    Ok(())
}
