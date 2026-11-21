//! Verify the live data path before any Btrfs probing.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::invalid;

pub fn sole_backing(mapped: &Path) -> io::Result<PathBuf> {
    let mut slaves = fs::read_dir(mapped.join("slaves"))?;
    let backing = slaves.next().transpose()?;
    match backing {
        Some(backing) if slaves.next().transpose()?.is_none() => fs::canonicalize(backing.path()),
        _ => Err(invalid("Host storage mapping requires exactly one backing device")),
    }
}

fn device(block: &Path) -> io::Result<String> {
    let device = fs::read_to_string(block.join("dev"))?;
    Ok(device.trim_end().to_owned())
}

fn unprobed_device(block: &Path) -> io::Result<String> {
    let id = device(block)?;
    let properties = fs::read_to_string(format!("/run/udev/data/b{id}"))?;
    if !properties.lines().any(|line| line == "E:DM_UDEV_DISABLE_DISK_RULES_FLAG=1")
        || properties.lines().any(|line| line.starts_with("E:ID_FS_"))
    {
        return Err(invalid("automatic probing of an authenticated Host storage mapping was not disabled"));
    }
    Ok(id)
}

fn table(device: &str) -> io::Result<String> {
    let (major, minor) = device.split_once(':').ok_or_else(|| invalid("invalid block device ID"))?;
    let result = Command::new("/usr/bin/dmsetup")
        .env_clear()
        .args(["table", "--major", major, "--minor", minor])
        .output()?;
    if !result.status.success() {
        return Err(invalid("could not inspect the active Host device-mapper table"));
    }
    let raw = String::from_utf8(result.stdout).map_err(io::Error::other)?;
    let line = raw.strip_suffix('\n').filter(|line| !line.contains('\n'))
        .ok_or_else(|| invalid("Host storage requires a single active device-mapper target"))?;
    // dmsetup masks raw keys by default. No table output is logged.
    Ok(line.to_owned())
}

fn positive(value: &str) -> Option<u64> {
    value.parse().ok().filter(|&number| number != 0)
}

pub fn verify(volume: &Path, partition: &Path) -> io::Result<PathBuf> {
    let volume_id = unprobed_device(volume)?;
    let journal = sole_backing(volume)?;
    if !journal.join("dm").is_dir() || sole_backing(&journal)? != partition {
        return Err(invalid("authenticated Host storage requires a journal over the selected partition"));
    }
    let journal_id = unprobed_device(&journal)?;
    let top = table(&volume_id)?;
    let fields: Vec<_> = top.split_ascii_whitespace().collect();
    let ["0", length, "crypt", "capi:authenc(hmac(sha256),xts(aes))-plain64", key, "0", source, "0", "2",
         "integrity:32:aead", "sector_size:4096"] = fields.as_slice()
    else {
        return Err(invalid("Host storage requires the approved AES-XTS and HMAC-SHA256 crypt target"));
    };
    if !key.starts_with(":96:logon:cryptsetup:") || *source != journal_id
        || !positive(length).is_some_and(|sectors| sectors.is_multiple_of(8))
    {
        return Err(invalid("authenticated Host crypt target has an unexpected key or device layout"));
    }

    let lower = table(&journal_id)?;
    let fields: Vec<_> = lower.split_ascii_whitespace().collect();
    let ["0", covered, "integrity", source, offset, "32", "J", "7", "block_size:4096",
         "interleave_sectors:32768", "buffer_sectors:128", journal_sectors, "journal_watermark:50",
         "commit_time:10000", "fix_padding"] = fields.as_slice()
    else {
        return Err(invalid("Host storage requires the approved journaled dm-integrity target"));
    };
    if covered != length || *source != device(partition)?
        || !positive(offset).is_some_and(|sectors| sectors.is_multiple_of(8))
        || journal_sectors.strip_prefix("journal_sectors:").and_then(positive).is_none()
    {
        return Err(invalid("Host integrity journal does not cover the selected crypt target and partition"));
    }
    Ok(journal)
}
