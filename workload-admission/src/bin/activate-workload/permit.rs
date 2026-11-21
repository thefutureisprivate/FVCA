//! Monitor the already mounted workload without reauthorizing an expired start.

use std::fs::{self, OpenOptions, TryLockError};
use std::io::{self, Read};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use fvca_workload_admission::VerifiedWorkload;
use fvca_workload_admission::revocation::{Action, PermitIdentity};
use serde::{Deserialize, Serialize};

use super::{
    DIRECTORY, Result, lifecycle_file, private_directory, read_trust, remove_missing,
    require_guest_data, stage, stop_workload,
};

const ACTIVE: &str = "/run/fvca/workload-image/permit.json";
const STATUS_DIRECTORY: &str = "/run/fvca/workload-image/permit-status";
const STATUS: &str = "/run/fvca/workload-image/permit-status/status.json";
const TEMPORARY: &str = "/run/fvca/workload-image/permit-status/.status.new";
const LIMIT: u64 = 32 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Mounted {
    authorization: String,
    service: String,
    valid_from: u64,
    start_until: u64,
    permit: PermitIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Condition {
    Current,
    ClockBeforeAuthorization,
    DeploymentExpired,
    PermitExpired,
    RevokedBlockNewStarts,
    RevokedStop,
    RevocationStateUnavailable,
}

fn condition(now: u64, mounted: &Mounted, action: Option<Action>) -> Condition {
    match action {
        Some(Action::Stop) => Condition::RevokedStop,
        Some(Action::BlockNewStarts) => Condition::RevokedBlockNewStarts,
        None if now >= mounted.permit.expires() => Condition::PermitExpired,
        None if now >= mounted.start_until => Condition::DeploymentExpired,
        None if now < mounted.valid_from => Condition::ClockBeforeAuthorization,
        None => Condition::Current,
    }
}

pub(super) fn record(workload: &VerifiedWorkload) -> Result<()> {
    if let Some(permit) = workload.permit() {
        fs::DirBuilder::new().mode(0o700).create(STATUS_DIRECTORY)?;
        let mounted = Mounted {
            authorization: workload.authorization_digest().to_owned(),
            service: workload.service().to_owned(),
            valid_from: workload.valid_from(),
            start_until: workload.expires(),
            permit: permit.clone(),
        };
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(ACTIVE)?;
        serde_json::to_writer(file, &mounted)?;
    }
    Ok(())
}

fn mounted() -> Result<Option<Mounted>> {
    private_directory(DIRECTORY)?;
    let file = match stage::private_file(Path::new(ACTIVE)) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut bytes = Vec::new();
    file.take(LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > LIMIT {
        return Err(io::Error::other("mounted permit state exceeds its bound").into());
    }
    let mounted: Mounted = serde_json::from_slice(&bytes)?;
    if stage::mounted_authorization()?.as_deref() != Some(mounted.authorization.as_str()) {
        return Err(io::Error::other("mounted permit does not match the verified workload").into());
    }
    Ok(Some(mounted))
}

pub(super) fn check_start(authorization: &str, valid_from: u64, start_until: u64) -> Result<()> {
    let mounted = mounted()?.ok_or_else(|| io::Error::other("missing mounted unsigned permit"))?;
    if mounted.authorization != authorization
        || mounted.valid_from != valid_from
        || mounted.start_until != start_until
    {
        return Err(io::Error::other("unsigned permit differs from the loaded service").into());
    }
    if revocation(&mounted)?.is_some() {
        return Err(io::Error::other("unsigned workload permit is revoked").into());
    }
    Ok(())
}

fn revocation(mounted: &Mounted) -> Result<Option<Action>> {
    let device = require_guest_data("nodev,nosuid,noexec")?.dev();
    let trust = read_trust(device)?;
    trust.permit_revocation(&mounted.permit)
}

fn publish(mounted: &Mounted, condition: Condition) -> Result<()> {
    let status = serde_json::json!({
        "schema": "fvca-workload-permit-status-v1",
        "condition": condition,
        "provenance": "UNSIGNED_UPSTREAM_APPROVED",
        "service": mounted.service,
        "authorization": mounted.authorization,
        "permit_id": mounted.permit.id(),
        "permit_expires": mounted.permit.expires(),
        "start_until": mounted.start_until,
    });
    let line = serde_json::to_string(&status)?;
    let body = format!("{line}\n");
    let unchanged = match stage::private_file(Path::new(STATUS)) {
        Ok(file) => {
            let mut old = Vec::new();
            file.take(LIMIT + 1).read_to_end(&mut old)?;
            old == body.as_bytes()
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    if unchanged {
        return Ok(());
    }
    remove_missing(fs::remove_file(TEMPORARY))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(TEMPORARY)?;
    io::Write::write_all(&mut file, body.as_bytes())?;
    fs::rename(TEMPORARY, STATUS)?;
    if condition == Condition::Current {
        println!("FVCA_WORKLOAD_PERMIT_STATUS {line}");
    } else {
        eprintln!("<4>FVCA_WORKLOAD_PERMIT_STATUS {line}");
    }
    Ok(())
}

pub(super) fn monitor() -> Result<()> {
    let lease = lifecycle_file()?;
    match lease.try_lock() {
        Ok(()) => (),
        Err(TryLockError::WouldBlock) => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    if !stage::directory_present(Path::new(DIRECTORY))? {
        return Ok(());
    }
    let mounted = match mounted() {
        Ok(Some(mounted)) => mounted,
        Ok(None) => return Ok(()),
        Err(error) => {
            remove_missing(fs::remove_file(STATUS))?;
            return Err(error);
        }
    };
    let action = match revocation(&mounted) {
        Ok(action) => action,
        Err(error) => {
            publish(&mounted, Condition::RevocationStateUnavailable)?;
            return Err(error);
        }
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |time| time.as_secs());
    let condition = condition(now, &mounted, action);
    if condition == Condition::RevokedStop {
        // The signed stop is independent of time and of an ordinary expiry warning.
        stop_workload()?;
    }
    publish(&mounted, condition)
}

pub(super) fn clear() -> io::Result<()> {
    for path in [ACTIVE, STATUS, TEMPORARY] {
        remove_missing(fs::remove_file(path))?;
    }
    remove_missing(fs::remove_dir(STATUS_DIRECTORY))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_an_explicit_stop_revocation_stops_an_already_running_workload() -> Result<()> {
        let mounted: Mounted = serde_json::from_value(json!({
            "authorization": "fixture", "service": "mail", "valid_from": 10, "start_until": 60,
            "permit": {"guest":"guest", "service":"mail", "id":"fixture", "permit":"fixture",
                       "authority":"fixture", "issued_at":10, "expires":90},
        }))?;
        assert_eq!(
            condition(0, &mounted, None),
            Condition::ClockBeforeAuthorization
        );
        assert_eq!(condition(10, &mounted, None), Condition::Current);
        assert_eq!(condition(60, &mounted, None), Condition::DeploymentExpired);
        assert_eq!(condition(90, &mounted, None), Condition::PermitExpired);
        assert_eq!(
            condition(90, &mounted, Some(Action::BlockNewStarts)),
            Condition::RevokedBlockNewStarts
        );
        for now in [0, 30, 90] {
            assert_eq!(
                condition(now, &mounted, Some(Action::Stop)),
                Condition::RevokedStop
            );
        }
        Ok(())
    }
}
