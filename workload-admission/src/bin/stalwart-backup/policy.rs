use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::Path;

use fvca_workload_admission::{read_bounded, verify_signature};
use openssl::x509::X509;
use serde::{Deserialize, Serialize};

use super::{Result, invalid};

pub const PROFILE: &str = "fvca-stalwart-sqlite-inline-v1";
pub const DB: &str = "stalwart.db";
pub const MANIFEST: &str = "manifest.json";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub schema: String,
    pub endpoint: Endpoint,
    pub timeout_seconds: u64,
    pub bandwidth_kib: u64,
    pub max_application_bytes: u64,
    pub operation: Operation,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub address: SocketAddr,
    pub bucket: String,
    pub prefix: String,
    pub region: String,
    pub repository: String,
    pub ca_sha256: String,
    pub restic_sha256: String,
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Create {
        source: Source,
        partition: String,
        filesystem: String,
        configuration: Vec<String>,
    },
    Recover {
        snapshot: String,
        manifest_sha256: String,
        deployment_sha256: String,
    },
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub vm_repository: String,
    pub vm_snapshot: String,
    pub vm_manifest_sha256: String,
    pub deployment_sha256: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: String,
    pub application_repository: String,
    pub source: ManifestSource,
    pub members: Vec<Member>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestSource {
    pub selection: Source,
    pub capture: String,
    pub captured: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Member {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

pub fn hash(value: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(hex) {
        return Err(invalid("expected a full lowercase SHA-256 or restic ID"));
    }
    Ok(())
}

fn hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

pub fn uuid(value: &str) -> Result<()> {
    if value.len() != 36 || !value.bytes().enumerate().all(|(i, byte)| match i {
        8 | 13 | 18 | 23 => byte == b'-',
        _ => hex(byte),
    }) {
        return Err(invalid("expected a canonical UUID"));
    }
    Ok(())
}

fn file_name(value: &str) -> bool {
    (1..=128).contains(&value.len()) && !value.starts_with('.')
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}

fn component(value: &str, min: usize, max: usize) -> bool {
    let alnum = |b: u8| b.is_ascii_digit() || b.is_ascii_lowercase();
    (min..=max).contains(&value.len())
        && value.bytes().all(|b| alnum(b) || b == b'-')
        && value.bytes().next().is_some_and(alnum) && value.bytes().last().is_some_and(alnum)
}

impl Source {
    pub fn validate(&self, repository: &str) -> Result<()> {
        for item in [&self.vm_repository, &self.vm_snapshot, &self.vm_manifest_sha256, &self.deployment_sha256] {
            hash(item)?;
        }
        if self.vm_repository == repository {
            return Err(invalid("the application backup requires its own repository"));
        }
        Ok(())
    }
}

impl Policy {
    pub fn approved(policy: &Path, signature: &Path, authority: &Path) -> Result<Self> {
        let text = read_bounded(policy, 32_768)?;
        let signature = read_bounded(signature, 16_384)?;
        let certificate = X509::from_pem(&read_bounded(authority, 16_384)?)?;
        verify_signature(&text, &signature, &certificate)?;
        let approved: Self = serde_json::from_slice(&text)?;
        let endpoint = &approved.endpoint;
        if approved.schema != PROFILE || !(1..=604800).contains(&approved.timeout_seconds)
            || !(1..=1048576).contains(&approved.bandwidth_kib)
            || approved.max_application_bytes == 0 || approved.max_application_bytes > 1 << 40
            || endpoint.address.port() == 0 || endpoint.address.ip().is_unspecified() || endpoint.address.ip().is_multicast()
            || !component(&endpoint.bucket, 3, 63) || !component(&endpoint.region, 1, 40)
            || endpoint.prefix.len() > 160
            || (!endpoint.prefix.is_empty() && !endpoint.prefix.split('/').all(|p| component(p, 1, 63)))
        {
            return Err(invalid("invalid signed Stalwart application backup profile or limits"));
        }
        for item in [&endpoint.repository, &endpoint.ca_sha256, &endpoint.restic_sha256] {
            hash(item)?;
        }
        match &approved.operation {
            Operation::Create { source, partition, filesystem, configuration } => {
                source.validate(&endpoint.repository)?;
                uuid(partition)?;
                uuid(filesystem)?;
                if configuration.len() > 64 || !configuration.iter().any(|file| file == "config.json")
                    || !configuration.iter().all(|file| file_name(file))
                    || configuration.iter().collect::<BTreeSet<_>>().len() != configuration.len()
                {
                    return Err(invalid("invalid signed application configuration inventory"));
                }
            }
            Operation::Recover { snapshot, manifest_sha256, deployment_sha256 } => {
                for item in [snapshot, manifest_sha256, deployment_sha256] {
                    hash(item)?;
                }
            }
        }
        Ok(approved)
    }
}

impl Member {
    pub fn valid(&self) -> Result<()> {
        hash(&self.sha256)?;
        if self.bytes == 0 || (self.path != "data/stalwart.db"
            && !self.path.strip_prefix("config/").is_some_and(file_name))
        {
            return Err(invalid("unexpected application recovery member"));
        }
        Ok(())
    }
}
