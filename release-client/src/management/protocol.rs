use std::io;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use fvca_trial_authorization::guest::SERVICE_GUEST_UUID;
use fvca_trial_authorization::guest_config::{Binding, Configuration, Resources};
use fvca_trial_authorization::{MANAGEMENT_UID, private_management_address};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::local_captures::Cursor;
use crate::{Result, channel, invalid, valid_digest, valid_uuid};

pub(super) const REQUEST_BYTES: usize = 2048;
pub(super) const RESPONSE_BYTES: usize = 4096;
pub(super) const ALPN: &[u8] = b"fvca-management/1";
pub(super) const VALIDITY_SECONDS: u64 = 30;

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
    pub apply_operator_public_key: Option<String>,
    pub(super) attestation_operator_public_key: Option<String>,
}

impl Enrollment {
    pub fn validate(&self) -> Result<()> {
        if self.schema != "fvca-hypervisor-management-v1"
            || !valid_uuid(&self.host)
            || self.host.as_bytes() == SERVICE_GUEST_UUID.to_bytes()
            || !private_management_address(self.address)
            || self.gateway_uid != MANAGEMENT_UID
            || self.gateway_gid != MANAGEMENT_UID
            || !valid_digest(&self.tls_certificate_sha256)
            || !valid_digest(&self.operator_public_key)
            || self.operator_public_key.bytes().all(|byte| byte == b'0')
            || self.apply_operator_public_key.as_ref().is_some_and(|key| {
                !valid_digest(key)
                    || key == &self.operator_public_key
                    || key.bytes().all(|byte| byte == b'0')
            })
            || self
                .attestation_operator_public_key
                .as_ref()
                .is_some_and(|key| {
                    !valid_digest(key)
                        || key == &self.operator_public_key
                        || Some(key) == self.apply_operator_public_key.as_ref()
                        || key.bytes().all(|byte| byte == b'0')
                })
        {
            return Err(invalid("invalid Hypervisor management enrollment").into());
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Expected {
    revision: u64,
    sha256: String,
}

impl From<Expected> for Binding {
    fn from(selected: Expected) -> Self {
        Self {
            revision: selected.revision,
            sha256: selected.sha256,
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum Operation {
    // Struct variants make Serde check extra fields even when there are no operands.
    Status {},
    HostStorageHealth {},
    HostBackupStatus {},
    HostLocalCaptures {
        after: Option<Cursor>,
    },
    HostLocalCapture {
        capture_id: String,
    },
    BootQuote {
        #[serde(deserialize_with = "boot_challenge")]
        challenge: [u8; 32],
    },
    Preflight {
        expected: Option<Expected>,
        vcpus: u32,
        memory_mib: u32,
    },
    ApplyConfiguration {
        plan: Plan,
    },
    #[serde(rename = "configuration-operation")]
    InspectConfiguration {
        operation_id: String,
    },
}

fn boot_challenge<'de, D: serde::Deserializer<'de>>(
    input: D,
) -> std::result::Result<[u8; 32], D::Error> {
    let value = String::deserialize(input)?;
    let mut challenge = [0; 32];
    if !valid_digest(&value)
        || hex::decode_to_slice(value, &mut challenge).is_err()
        || challenge == [0; 32]
    {
        return Err(serde::de::Error::custom("invalid boot quote challenge"));
    }
    Ok(challenge)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Plan {
    pub expected: Option<Expected>,
    pub next: Expected,
    pub vcpus: u32,
    pub memory_mib: u32,
    pub planned_at: u64,
    pub plan_expires: u64,
}

impl Plan {
    pub fn valid_at(&self, now: u64) -> bool {
        self.plan_expires.saturating_sub(self.planned_at) <= 900
            && (self.planned_at..self.plan_expires).contains(&now)
    }
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
    let request: Request = serde_json::from_slice(body)?;
    let key = match &request.operation {
        Operation::ApplyConfiguration { .. } => enrollment
            .apply_operator_public_key
            .as_deref()
            .ok_or_else(|| invalid("the Host has no management configuration submitter"))?,
        Operation::BootQuote { .. } => enrollment
            .attestation_operator_public_key
            .as_deref()
            .ok_or_else(|| invalid("the Host has no attestation operator"))?,
        Operation::Status {}
        | Operation::HostStorageHealth {}
        | Operation::HostBackupStatus {}
        | Operation::HostLocalCaptures { .. }
        | Operation::HostLocalCapture { .. }
        | Operation::Preflight { .. }
        | Operation::InspectConfiguration { .. } => &enrollment.operator_public_key,
    };
    channel::verify(
        &hex::decode(key)?,
        body,
        signature,
        "invalid management request signature",
    )?;
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
    pub revision: Option<u64>,
    pub sha256: Option<String>,
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

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Refusal {
    TrialInProgress,
    StaleConfiguration,
    OutsideMachineProfile,
    ConfigurationAuthorityUnavailable,
    ConfigurationExhausted,
    HostStateUnavailable,
    InvalidConfigurationPlan,
    ExpiredConfigurationPlan,
    ConfigurationOperationPending,
    UnknownConfigurationOperation,
    LifecycleBusy,
    OutsideHostCapacity,
    BootQuoteUnavailable,
    HostStorageHealthUnavailable,
    HostBackupStatusUnavailable,
    HostCaptureCatalogUnavailable,
    UnknownHostCapture,
    InvalidHostCaptureCursor,
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

    #[test]
    fn confines_operators_to_their_enrolled_operations() -> Result<()> {
        let key = || -> Result<Ed25519KeyPair> {
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())?;
            Ok(Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())?)
        };
        let reader = key()?;
        let submitter = key()?;
        let verifier = key()?;
        let host = "367f5cbc-c46a-437d-af72-5d96d805d234";
        let mut enrollment: Enrollment = serde_json::from_value(json!({
            "schema": "fvca-hypervisor-management-v1",
            "host": host, "address": "127.0.0.1:8443", "gateway_uid": 62000, "gateway_gid": 62000,
            "tls_certificate_sha256": "b".repeat(64),
            "operator_public_key": hex::encode(reader.public_key().as_ref()),
            "apply_operator_public_key": hex::encode(submitter.public_key().as_ref()),
            "attestation_operator_public_key": hex::encode(verifier.public_key().as_ref()),
        }))?;
        enrollment.validate()?;
        let request = |operation, key: &Ed25519KeyPair| -> Result<Vec<u8>> {
            let body = serde_json::to_vec(&json!({
                "schema": "fvca-management-request-v1", "host": host, "guest": SERVICE_GUEST_UUID.to_str()?,
                "nonce": "4".repeat(32), "issued_at": 10, "expires": 40, "operation": operation,
            }))?;
            let mut packet = key.sign(&body).as_ref().to_vec();
            packet.extend_from_slice(&body);
            Ok(packet)
        };
        let mutation = json!({"type": "apply-configuration", "plan": {
            "expected": null, "next": {"revision": 1, "sha256": "c".repeat(64)},
            "vcpus": 3, "memory_mib": 2560, "planned_at": 5, "plan_expires": 300,
        }});
        let read = json!({"type": "configuration-operation", "operation_id": "d".repeat(64)});
        let health = json!({"type": "host-storage-health"});
        let backup = json!({"type": "host-backup-status"});
        let catalog = json!({"type": "host-local-captures"});
        let capture = json!({"type": "host-local-capture", "capture_id": host});
        let quote = json!({"type": "boot-quote", "challenge": "a4".repeat(32)});
        assert!(authorize(&enrollment, &request(mutation.clone(), &reader)?, 20).is_err());
        assert!(authorize(&enrollment, &request(mutation.clone(), &verifier)?, 20).is_err());
        let write = request(mutation, &submitter)?;
        assert!(matches!(
            authorize(&enrollment, &write, 20)?.operation,
            Operation::ApplyConfiguration { .. }
        ));
        assert!(authorize(&enrollment, &request(read.clone(), &submitter)?, 20).is_err());
        assert!(authorize(&enrollment, &request(read.clone(), &verifier)?, 20).is_err());
        for other in [&submitter, &verifier] {
            assert!(authorize(&enrollment, &request(health.clone(), other)?, 20).is_err());
            assert!(authorize(&enrollment, &request(backup.clone(), other)?, 20).is_err());
            assert!(authorize(&enrollment, &request(catalog.clone(), other)?, 20).is_err());
            assert!(authorize(&enrollment, &request(capture.clone(), other)?, 20).is_err());
        }
        assert!(matches!(
            authorize(&enrollment, &request(health, &reader)?, 20)?.operation,
            Operation::HostStorageHealth {}
        ));
        assert!(matches!(
            authorize(&enrollment, &request(backup, &reader)?, 20)?.operation,
            Operation::HostBackupStatus {}
        ));
        assert!(matches!(
            authorize(&enrollment, &request(catalog, &reader)?, 20)?.operation,
            Operation::HostLocalCaptures { after: None }
        ));
        assert!(matches!(
            authorize(&enrollment, &request(capture, &reader)?, 20)?.operation,
            Operation::HostLocalCapture { capture_id } if capture_id == host
        ));
        for invalid in [
            json!({"type": "status", "path": "/etc/shadow"}),
            json!({"type": "host-storage-health", "reset": true}),
            json!({"type": "host-storage-health", "pool": "/run/fvca/guest-data"}),
            json!({"type": "host-backup-status", "start": true}),
            json!({"type": "host-backup-status", "repository": "arbitrary"}),
            json!({"type": "host-local-captures", "expire": true}),
            json!({"type": "host-local-capture", "capture_id": host, "path": "/etc/shadow"}),
        ] {
            assert!(authorize(&enrollment, &request(invalid, &reader)?, 20).is_err());
        }
        assert!(matches!(
            authorize(&enrollment, &request(read, &reader)?, 20)?.operation,
            Operation::InspectConfiguration { .. }
        ));
        for other in [&reader, &submitter] {
            assert!(authorize(&enrollment, &request(quote.clone(), other)?, 20).is_err());
        }
        for invalid in ["0".repeat(64), "A4".repeat(32), "a4".repeat(31)] {
            let malformed = json!({"type": "boot-quote", "challenge": invalid});
            assert!(authorize(&enrollment, &request(malformed, &verifier)?, 20).is_err());
        }
        let quote = request(quote, &verifier)?;
        assert!(matches!(
            authorize(&enrollment, &quote, 20)?.operation,
            Operation::BootQuote { challenge } if challenge == [0xa4; 32]
        ));
        enrollment.attestation_operator_public_key = enrollment.apply_operator_public_key.clone();
        assert!(enrollment.validate().is_err());
        enrollment.attestation_operator_public_key = None;
        assert!(authorize(&enrollment, &quote, 20).is_err());
        enrollment.apply_operator_public_key = None;
        assert!(authorize(&enrollment, &write, 20).is_err());
        enrollment.apply_operator_public_key = Some(enrollment.operator_public_key.clone());
        assert!(enrollment.validate().is_err());
        Ok(())
    }
}
