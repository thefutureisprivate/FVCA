//! Carry a separately authorized configuration through trial and promotion.

use std::fs::{self, File};
use std::io::{self, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::Path;

use fvca_trial_authorization::guest_config::{self, Binding, Change, Policy};

use super::{APPROVAL_LIMIT, HOST_DATA, publish, read, read_record, verify_signature};
use crate::{invalid, recovery};

const COMMITTED: &str = "guest-configuration-active";

pub fn verify_key(cmdline: &str) -> io::Result<()> {
    let authorized = guest_config::authority(cmdline)?;
    let enrolled = match read(Path::new(guest_config::AUTHORITY_FILE), 32) {
        Ok(raw) => Some(
            <[u8; 32]>::try_from(raw)
                .map_err(|_| invalid("invalid Guest configuration authority"))?,
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    if authorized != enrolled {
        return Err(invalid(
            "Guest configuration authority differs from the signed UKI",
        ));
    }
    Ok(())
}

fn optional_record(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match read_record(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn authorize(packet: &[u8]) -> io::Result<Change> {
    guest_config::signed_change(packet)?;
    Change::parse(verify_signature("guest-configuration", packet)?.as_bytes())
}

fn trial_change(
    directory: &Path,
    tx: &str,
    attempt: &[u8],
) -> io::Result<Option<(Vec<u8>, Change)>> {
    let Some(packet) =
        optional_record(&directory.join(format!("{tx}{}", guest_config::CHANGE_SUFFIX)))?
    else {
        return Ok(None);
    };
    let change = authorize(&packet)?;
    if attempt.len() > APPROVAL_LIMIT {
        return Err(invalid("trial approval exceeds its size bound"));
    }
    let (reader, mut writer) = UnixStream::pair()?;
    writer.write_all(attempt)?;
    drop(writer);
    change.require_trial(&recovery::sha256(File::from(OwnedFd::from(reader)))?)?;
    Ok(Some((packet, change)))
}

fn committed(directory: &Path) -> io::Result<Option<(Vec<u8>, Change)>> {
    let Some(packet) = optional_record(&directory.join(COMMITTED))? else {
        return Ok(None);
    };
    let change = authorize(&packet)?;
    Ok(Some((packet, change)))
}

pub fn require_committed(cmdline: &str) -> io::Result<()> {
    let directory = Path::new(HOST_DATA).join("boot-trials");
    if let Some((_, change)) = committed(&directory)?
        && guest_config::binding(cmdline)?.as_ref() != Some(&change.next)
    {
        return Err(invalid(
            "Host boot selects a superseded Guest configuration",
        ));
    }
    Ok(())
}

fn expected(candidate: Option<&Binding>, authority: Option<[u8; 32]>, changed: bool) -> Vec<u8> {
    let binding = candidate.map_or_else(
        || "profile-default\n".into(),
        |binding| format!("{},{}\n", binding.revision, binding.sha256),
    );
    let mut record = authority.map_or_else(Vec::new, |key| key.to_vec());
    if changed {
        record.extend_from_slice(b"change\n");
    }
    record.extend_from_slice(binding.as_bytes());
    record
}

pub(super) fn reserve(
    directory: &Path,
    tx: &str,
    attempt: &[u8],
    cmdline: &str,
    first: bool,
) -> io::Result<()> {
    let Policy { binding, authority } = Policy::parse(cmdline)?;
    let requested = trial_change(directory, tx, attempt)?;
    let selected = match &requested {
        Some((_, change)) => {
            if authority.is_none() || change.previous != binding {
                return Err(invalid(
                    "Guest configuration change has a stale expected revision or authority",
                ));
            }
            let promotion = read_record(&directory.join(format!("{tx}.standing-promotion")))?;
            fvca_trial_authorization::Promotion::parse(verify_signature("promotion", &promotion)?)?
                .matches_trial(attempt)?;
            Some(&change.next)
        }
        None => binding.as_ref(),
    };
    let record = directory.join(format!("{tx}.guest-configuration"));
    let value = expected(selected, authority, requested.is_some());
    match read_record(&record) {
        Ok(prior) if prior == value => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound && first => publish(&record, &value),
        Ok(_) => Err(invalid(
            "standing Host trial changes the reserved Guest configuration",
        )),
        Err(error) => Err(error),
    }
}

fn verify_candidate(
    directory: &Path,
    tx: &str,
    attempt: &[u8],
    cmdline: &str,
) -> io::Result<Option<(Vec<u8>, Change)>> {
    let Policy { binding, authority } = Policy::parse(cmdline)?;
    let requested = trial_change(directory, tx, attempt)?;
    if let Some((_, change)) = &requested
        && (authority.is_none() || binding.as_ref() != Some(&change.next))
    {
        return Err(invalid(
            "candidate does not select its authorized Guest configuration",
        ));
    }
    if read_record(&directory.join(format!("{tx}.guest-configuration")))?
        != expected(binding.as_ref(), authority, requested.is_some())
    {
        return Err(invalid(
            "candidate changes the reserved Guest configuration or authority",
        ));
    }
    Ok(requested)
}

pub(super) fn trial(directory: &Path, tx: &str, attempt: &[u8], cmdline: &str) -> io::Result<()> {
    if let Some((_, change)) = verify_candidate(directory, tx, attempt, cmdline)? {
        if let Some((_, active)) = committed(directory)?
            && Some(active.next) != change.previous
        {
            return Err(invalid(
                "Guest configuration change no longer advances the committed revision",
            ));
        }
    } else {
        require_committed(cmdline)?;
    }
    Ok(())
}

pub(super) fn confirm(directory: &Path, tx: &str, attempt: &[u8], cmdline: &str) -> io::Result<()> {
    let Some((packet, change)) = verify_candidate(directory, tx, attempt, cmdline)? else {
        return require_committed(cmdline);
    };
    if let Some((prior, active)) = committed(directory)? {
        if prior == packet {
            return Ok(());
        }
        if Some(active.next) != change.previous {
            return Err(invalid(
                "Guest configuration promotion has a stale expected revision",
            ));
        }
    }
    let next = directory.join("guest-configuration-active.next");
    match fs::remove_file(&next) {
        Ok(()) => (),
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error),
    }
    publish(&next, &packet)?;
    fs::rename(next, directory.join(COMMITTED))?;
    File::open(directory)?.sync_all()?;
    println!(
        "FVCA_GUEST_CONFIGURATION_COMMITTED {tx} {}",
        change.next.revision
    );
    Ok(())
}
