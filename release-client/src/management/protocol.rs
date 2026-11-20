use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use fvca_trial_authorization::guest::SERVICE_GUEST_UUID;
use fvca_trial_authorization::guest_config::{Binding, Configuration, Resources};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{Result, channel, invalid, valid_digest};

pub(super) const REQUEST_BYTES: usize = 2048;
pub(super) const RESPONSE_BYTES: usize = 4096;
pub(super) const ALPN: &[u8] = b"fvca-management/1";
const VALIDITY_SECONDS: u64 = 30;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Enrollment {
    schema: String,
    pub host: String,
    pub address: SocketAddr,
    pub gateway_uid: u32,
    pub gateway_gid: u32,
    pub tls_certificate_sha256: String,
    operator_public_key: String,
}

impl Enrollment {
    pub fn validate(&self) -> Result<()> {
        let private = match self.address.ip() {
            IpAddr::V4(ip) => ip.is_private() || ip.is_loopback(),
            IpAddr::V6(ip) => ip.is_unique_local() || ip.is_loopback(),
        };
        if self.schema != "fvca-hypervisor-management-v1"
            || !uuid(&self.host)
            || self.host.as_bytes() == SERVICE_GUEST_UUID.to_bytes()
            || !private
            || self.address.port() < 1024
            || !(1..u32::MAX).contains(&self.gateway_uid)
            || !(1..u32::MAX).contains(&self.gateway_gid)
            || !valid_digest(&self.tls_certificate_sha256)
            || !valid_digest(&self.operator_public_key)
            || self.operator_public_key.bytes().all(|byte| byte == b'0')
        {
            return Err(invalid("invalid Hypervisor management enrollment").into());
        }
        Ok(())
    }
}

fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
        && value != "00000000-0000-0000-0000-000000000000"
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Expected {
    revision: u64,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum Operation {
    Status,
    Preflight {
        expected: Option<Expected>,
        vcpus: u32,
        memory_mib: u32,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    schema: String,
    pub nonce: String,
    host: String,
    guest: String,
    issued_at: u64,
    expires: u64,
    pub operation: Operation,
}

pub(super) fn current_time() -> io::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs())
}

pub(super) fn authorize(enrollment: &Enrollment, packet: &[u8], now: u64) -> Result<Request> {
    let (signature, body) = packet
        .split_first_chunk::<64>()
        .filter(|_| packet.len() <= REQUEST_BYTES)
        .ok_or_else(|| invalid("invalid management request length"))?;
    channel::verify(
        &hex::decode(&enrollment.operator_public_key)?,
        body,
        signature,
        "invalid management request signature",
    )?;
    let request: Request = serde_json::from_slice(body)?;
    if request.schema != "fvca-management-request-v1"
        || request.host != enrollment.host
        || request.guest.as_bytes() != SERVICE_GUEST_UUID.to_bytes()
        || request.nonce.len() != 32
        || !request
            .nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || request.nonce.bytes().all(|byte| byte == b'0')
        || request.expires.saturating_sub(request.issued_at) > VALIDITY_SECONDS
        || !(request.issued_at..request.expires).contains(&now)
    {
        return Err(
            invalid("management request is outside its enrolled identity or validity").into(),
        );
    }
    Ok(request)
}

#[derive(Serialize)]
pub(super) struct Settings {
    revision: Option<u64>,
    sha256: Option<String>,
    vcpus: u32,
    memory_mib: u32,
}

impl Settings {
    pub fn new(binding: Option<Binding>, resources: Resources) -> Self {
        let (revision, sha256) = binding.map_or((None, None), |value| {
            (Some(value.revision), Some(value.sha256))
        });
        Self {
            revision,
            sha256,
            vcpus: resources.vcpus,
            memory_mib: resources.memory_mib,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Refusal {
    TrialInProgress,
    StaleConfiguration,
    OutsideMachineProfile,
    ConfigurationAuthorityUnavailable,
    ConfigurationExhausted,
    HostStateUnavailable,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Activation {
    None,
    HostTrial,
}

pub(super) fn preflight(
    running: Option<Binding>,
    current: Resources,
    expected: Option<&Expected>,
    next: Resources,
) -> std::result::Result<(Settings, Activation), Refusal> {
    match (&running, expected) {
        (None, None) => (),
        (Some(running), Some(expected))
            if running.revision == expected.revision && running.sha256 == expected.sha256 => {}
        _ => return Err(Refusal::StaleConfiguration),
    }
    if next == current {
        return Ok((Settings::new(running, next), Activation::None));
    }
    let revision = running
        .map_or(0, |binding| binding.revision)
        .checked_add(1)
        .ok_or(Refusal::ConfigurationExhausted)?;
    let configuration = Configuration::from_resources(revision, next)
        .map_err(|_| Refusal::OutsideMachineProfile)?;
    let record = configuration
        .record()
        .map_err(|_| Refusal::HostStateUnavailable)?;
    let binding = Binding {
        revision,
        sha256: channel::digest(record.as_bytes()),
    };
    Ok((Settings::new(Some(binding), next), Activation::HostTrial))
}

pub(super) async fn read_frame(
    stream: &mut (impl AsyncRead + Unpin),
    max: usize,
) -> io::Result<Vec<u8>> {
    let size = stream.read_u32().await? as usize;
    if !(1..=max).contains(&size) {
        return Err(invalid(
            "management frame exceeds its size bound or is empty",
        ));
    }
    let mut data = vec![0; size];
    stream.read_exact(&mut data).await?;
    Ok(data)
}

pub(super) async fn write_frame(
    stream: &mut (impl AsyncWrite + Unpin),
    data: &[u8],
    max: usize,
) -> io::Result<()> {
    let size = u32::try_from(data.len()).map_err(io::Error::other)?;
    if !(1..=max).contains(&data.len()) {
        return Err(invalid(
            "management frame exceeds its size bound or is empty",
        ));
    }
    stream.write_u32(size).await?;
    stream.write_all(data).await?;
    stream.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };
    use serde_json::json;

    #[test]
    fn verifies_operator_target_duration_nonce_and_exact_payload() -> Result<()> {
        let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())?;
        let key = Ed25519KeyPair::from_pkcs8(key.as_ref())?;
        let host = "367f5cbc-c46a-437d-af72-5d96d805d234";
        let enrollment: Enrollment = serde_json::from_value(json!({
            "schema": "fvca-hypervisor-management-v1",
            "host": host,
            "address": "127.0.0.1:8443",
            "gateway_uid": 62000,
            "gateway_gid": 62000,
            "tls_certificate_sha256": "b".repeat(64),
            "operator_public_key": hex::encode(key.public_key().as_ref()),
        }))?;
        enrollment.validate()?;
        let valid = json!({
            "schema": "fvca-management-request-v1",
            "host": host,
            "guest": SERVICE_GUEST_UUID.to_str()?,
            "nonce": "4".repeat(32),
            "issued_at": 10,
            "expires": 40,
            "operation": {"type": "status"},
        });
        let sign = |value: &serde_json::Value| -> Result<Vec<u8>> {
            let body = serde_json::to_vec(value)?;
            let mut packet = key.sign(&body).as_ref().to_vec();
            packet.extend_from_slice(&body);
            Ok(packet)
        };
        let mut packet = sign(&valid)?;
        authorize(&enrollment, &packet, 10)?;
        assert!(authorize(&enrollment, &packet, 9).is_err());
        assert!(authorize(&enrollment, &packet, 40).is_err());
        packet[0] ^= 1;
        assert!(authorize(&enrollment, &packet, 20).is_err());
        for (field, value) in [
            ("host", json!(SERVICE_GUEST_UUID.to_str()?)),
            ("guest", json!(host)),
            ("expires", json!(41)),
            ("nonce", json!("0".repeat(32))),
            ("operation", json!({"type": "apply", "path": "/example"})),
        ] {
            let mut changed = valid.clone();
            changed[field] = value;
            assert!(
                authorize(&enrollment, &sign(&changed)?, 20).is_err(),
                "{field}"
            );
        }
        Ok(())
    }

    #[test]
    fn preflight_uses_the_configuration_generation_instead_of_release_identity() {
        let desired = Resources {
            vcpus: 3,
            memory_mib: 2560,
        };
        let (plan, activation) = preflight(None, Resources::DEFAULT, None, desired).unwrap();
        assert!(matches!(activation, Activation::HostTrial));
        assert_eq!(plan.revision, Some(1));
        assert_eq!(
            plan.sha256.as_deref(),
            Some("d1bfe17ab1d4bba583943189bf1a98f40381038bf6b768d6d7ab0d4979b62b99")
        );
        let binding = Binding {
            revision: 1,
            sha256: plan.sha256.unwrap(),
        };
        let mut expected = Expected {
            revision: 1,
            sha256: binding.sha256.clone(),
        };
        let change = Resources {
            vcpus: 4,
            memory_mib: 3072,
        };
        let (plan, _) = preflight(Some(binding.clone()), desired, Some(&expected), change).unwrap();
        assert_eq!(plan.revision, Some(2));
        let (_, activation) =
            preflight(Some(binding.clone()), desired, Some(&expected), desired).unwrap();
        assert!(matches!(activation, Activation::None));
        expected.sha256 = "a".repeat(64);
        assert!(matches!(
            preflight(Some(binding), desired, Some(&expected), change),
            Err(Refusal::StaleConfiguration),
        ));
        assert!(matches!(
            preflight(
                None,
                Resources::DEFAULT,
                None,
                Resources {
                    vcpus: 5,
                    memory_mib: 2560
                }
            ),
            Err(Refusal::OutsideMachineProfile),
        ));
    }
}
