//! The Hypervisor's boot-authorized destination for Service Guest backups.

use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::Path;

use crate::{invalid, runtime};

pub const POLICY: &str = "/run/fvca/vm-backup-policy";
pub const CA: &str = "/run/fvca/vm-backup-ca.pem";
pub const CREDENTIALS: &str = "/run/fvca/host-data/backup-credentials";

pub struct Policy<'a> {
    pub endpoint: SocketAddr,
    pub bucket: &'a str,
    pub prefix: &'a str,
    pub region: &'a str,
    pub repository: &'a str,
}

fn component(value: &str, minimum: usize, maximum: usize) -> bool {
    let character = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    (minimum..=maximum).contains(&value.len())
        && value.as_bytes().first().copied().is_some_and(character)
        && value.as_bytes().last().copied().is_some_and(character)
        && value.bytes().all(|byte| character(byte) || byte == b'-')
}

pub fn parse(text: &str) -> io::Result<Policy<'_>> {
    if text.len() > 2048 || !text.ends_with('\n') {
        return Err(invalid("invalid backup policy size or terminator"));
    }
    let mut lines = text.lines();
    if lines.next() != Some("FVCA-VM-BACKUP-1") {
        return Err(invalid("unexpected backup policy version"));
    }
    let mut take = |key| lines.next().and_then(|line| line.strip_prefix(key))
        .ok_or_else(|| invalid("incomplete backup policy"));
    let endpoint: SocketAddr = take("endpoint=")?.parse().map_err(|_| invalid("expected a literal S3 IP address and port"))?;
    let bucket = take("bucket=")?;
    let prefix = take("prefix=")?;
    let region = take("region=")?;
    let repository = runtime::hash(take("repository=")?)?;
    if lines.next().is_some() || endpoint.port() == 0 || endpoint.ip().is_unspecified()
        || endpoint.ip().is_multicast() || !component(bucket, 3, 63) || !component(region, 1, 40)
        || prefix.len() > 160 || (!prefix.is_empty() && !prefix.split('/').all(|name| component(name, 1, 63)))
    {
        return Err(invalid("invalid registered S3 destination"));
    }
    Ok(Policy { endpoint, bucket, prefix, region, repository })
}

pub fn activate_if_selected() -> io::Result<()> {
    let path = Path::new("/usr/lib/fvca/vm-backup-policy");
    let certificate = Path::new("/usr/lib/fvca/vm-backup-ca.pem");
    if !path.try_exists()? && !certificate.try_exists()? {
        return Ok(());
    }
    let text = fs::read_to_string(path)?;
    let policy = parse(&text)?;
    let ca = fs::read(certificate)?;
    if ca.is_empty() || ca.len() > 65_536 || !ca.starts_with(b"-----BEGIN CERTIFICATE-----") {
        return Err(invalid("invalid backup trust bundle"));
    }
    fs::write(POLICY, &text)?;
    fs::write(CA, ca)?;
    let override_dir = Path::new("/run/systemd/system/fvca-backup-upload@.service.d");
    fs::create_dir_all(override_dir)?;
    fs::write(override_dir.join("20-egress.conf"),
              format!("[Service]\nIPAddressAllow={}\n", policy.endpoint.ip()))?;
    Ok(())
}
