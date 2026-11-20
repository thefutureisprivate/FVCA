//! Recovery-set identity selected by the independently signed Host UKI.

use std::fs::{self, File};
use std::io;
use std::process::{Command, Stdio};

use crate::{backup_policy, identity, invalid, runtime};

pub const AUTHORIZATION: &str = "/run/fvca/vm-restore-authorization";
pub const CREDENTIALS: &str = "/run/fvca/host-data/restore-credentials";

pub struct Request<'a> {
    pub capture: &'a str,
    pub restore: &'a str,
    pub snapshot: &'a str,
    pub repository: &'a str,
    pub manifest: &'a str,
    pub disk: &'a str,
    pub disk_bytes: u64,
    pub total_bytes: u64,
}

pub fn uuid(value: &str) -> io::Result<&str> {
    identity(value, "", &[8, 4, 4, 4, 12], '-')
}

impl<'a> Request<'a> {
    pub fn parse(text: &'a str) -> io::Result<Self> {
        if text.len() > 2048 || !text.ends_with('\n') || text.contains('\r') {
            return Err(invalid("invalid S3 restore authorization size or terminator"));
        }
        let mut lines = text.lines();
        if lines.next() != Some("FVCA-S3-RESTORE-1") || lines.next() != Some("identity=source-fenced") {
            return Err(invalid("restore requires an authorized fenced source identity"));
        }
        let mut take = |key| lines.next().and_then(|line| line.strip_prefix(key))
            .ok_or_else(|| invalid("incomplete S3 restore authorization"));
        let capture = uuid(take("capture=")?)?;
        let restore = uuid(take("restore=")?)?;
        let repository = runtime::hash(take("repository=")?)?;
        let snapshot = runtime::hash(take("snapshot=")?)?;
        let manifest = runtime::hash(take("manifest_sha256=")?)?;
        let disk = runtime::hash(take("disk_sha256=")?)?;
        let number = |text: &str| text.parse::<u64>().ok().filter(|number| number.to_string() == text)
            .ok_or_else(|| invalid("invalid signed recovery size"));
        let disk_bytes = number(take("disk_bytes=")?)?;
        let total_bytes = number(take("total_bytes=")?)?;
        if lines.next().is_some() || disk_bytes == 0 || !disk_bytes.is_multiple_of(512) || total_bytes <= disk_bytes {
            return Err(invalid("unexpected S3 restore authorization contents"));
        }
        Ok(Self { capture, restore, repository, snapshot, manifest, disk, disk_bytes, total_bytes })
    }

    pub fn key(&self) -> String {
        format!("{}.{}", self.capture, self.restore)
    }
}

pub fn activate_if_selected() -> io::Result<bool> {
    let text = match fs::read_to_string("/usr/lib/fvca/vm-restore-authorization") {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    let request = Request::parse(&text)?;
    let destination = fs::read_to_string(backup_policy::POLICY)?;
    if backup_policy::parse(&destination)?.repository != request.repository {
        return Err(invalid("restore authorization has a different repository"));
    }
    let directory = "/run/systemd/system/fvca-backup-download@.service.d";
    fs::create_dir_all(directory)?;
    fs::write(format!("{directory}/30-size.conf"), format!("[Service]\nLimitFSIZE={}\n", request.total_bytes))?;
    fs::write(AUTHORIZATION, text)?;
    Ok(true)
}

pub fn sha256(file: File) -> io::Result<String> {
    let output = Command::new("/usr/bin/sha256sum").env_clear().stdin(Stdio::from(file)).output()?;
    let text = std::str::from_utf8(&output.stdout).map_err(io::Error::other)?;
    if !output.status.success() {
        return Err(invalid("could not hash a recovery member"));
    }
    Ok(runtime::hash(text.strip_suffix("  -\n").ok_or_else(|| invalid("unexpected recovery digest output"))?)?.to_owned())
}
