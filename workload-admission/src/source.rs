//! Check the enrolled source policy and independently signed unsigned permits.

use base64::{Engine, engine::general_purpose::STANDARD};
use openssl::sha::sha256;
use serde::Deserialize;

use crate::records::{Deployment, Derivation, Platform, Provenance};
use crate::revocation::PermitIdentity;
use crate::{
    Launch, RECORD_LIMIT, Result, SIGNATURE_LIMIT, Trust, digest, invalid, is_digest, name,
    revocation_id, verify_signature,
};

#[derive(Deserialize)]
#[serde(
    tag = "provenance",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
enum Evidence {
    PublisherVerified {
        policy: String,
        proof: Vec<PublisherProof>,
    },
    UnsignedUpstreamApproved {
        policy: String,
        permit: String,
        signature: String,
        authority: String,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    schema: String,
    service: String,
    repository: String,
    index: String,
    manifest: String,
    uid: u16,
    gid: u16,
    volumes: Vec<String>,
    certificate_identity: Option<String>,
    certificate_issuer: Option<String>,
    permit_authority: Option<String>,
}

#[derive(Deserialize)]
struct PublisherProof {
    critical: Claim,
}

#[derive(Deserialize)]
struct Claim {
    #[serde(rename = "type")]
    kind: String,
    image: ClaimedImage,
    identity: ClaimedIdentity,
}

#[derive(Deserialize)]
struct ClaimedImage {
    #[serde(rename = "docker-manifest-digest")]
    digest: String,
}

#[derive(Deserialize)]
struct ClaimedIdentity {
    #[serde(rename = "docker-reference")]
    reference: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Permit {
    schema: String,
    provenance: Provenance,
    acknowledgment: Request,
    request_sha256: String,
    operator_certificate: String,
    delegation_sha256: String,
    issued_at: u64,
    discovery: Discovery,
    expiry_action: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RevocationAction {
    BlockNewStarts,
    Stop,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    operator: String,
    role: String,
    guest: String,
    service: String,
    repository: String,
    source_policy: String,
    source_index: String,
    manifest: String,
    platform: Platform,
    launch: String,
    acknowledgment: String,
    reason: String,
    requested_at: u64,
    expires: u64,
    revocation_id: String,
    #[serde(rename = "revocation_action")]
    _revocation_action: RevocationAction,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Discovery {
    schema: String,
    repository: String,
    subjects: [Subject; 2],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Subject {
    digest: String,
    referrers_api: Probe,
    referrers_tag: Probe,
    cosign_signature_tag: Probe,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Probe {
    status: u16,
    response: String,
}

pub(crate) struct Validity {
    pub valid_from: u64,
    pub expires: u64,
    pub permit: Option<PermitIdentity>,
}

fn decode(text: &str, limit: u64) -> Result<Vec<u8>> {
    let raw = STANDARD.decode(text)?;
    if raw.is_empty() || raw.len() as u64 > limit {
        return Err(invalid("source evidence member is empty or oversized"));
    }
    Ok(raw)
}

fn exact_policy(encoded: &str, derivation: &Derivation, launch: &Launch) -> Result<Policy> {
    let raw = decode(encoded, RECORD_LIMIT)?;
    if digest(&sha256(&raw)) != derivation.source_policy {
        return Err(invalid(
            "source evidence does not contain the reviewed policy bytes",
        ));
    }
    let policy: Policy = serde_json::from_slice(&raw)?;
    let source = &derivation.source;
    if policy.service != derivation.service
        || policy.repository != source.repository
        || policy.index != source.index
        || policy.manifest != derivation.manifest.digest
        || policy.certificate_identity != source.certificate_identity
        || policy.certificate_issuer != source.certificate_issuer
        || policy.permit_authority != source.permit_authority
        || (policy.uid, policy.gid) != (launch.uid, launch.gid)
        || policy.volumes != launch.volumes
    {
        return Err(invalid(
            "source policy differs from the derivation or normalized launch",
        ));
    }
    Ok(policy)
}

impl Permit {
    fn check(&self, derivation: &Derivation, deployment: &Deployment, now: u64) -> Result<()> {
        let request = &self.acknowledgment;
        if self.schema != "fvca-workload-unsigned-permit-v1"
            || self.provenance != Provenance::UnsignedUpstreamApproved
            || self.expiry_action != "block-new-starts"
            || request.schema != "fvca-workload-permit-request-v1"
            || request.role != "workload-unsigned-approver"
            || !name(&request.operator)
            || request.guest != deployment.guest
            || request.service != deployment.service
            || request.repository != derivation.source.repository
            || request.source_policy != derivation.source_policy
            || request.source_index != deployment.source_index
            || request.manifest != deployment.manifest
            || request.platform != derivation.platform
            || request.launch != deployment.launch
            || request.acknowledgment != "I KNOW THIS MIGHT BE INSECURE"
            || request.reason.is_empty()
            || request.reason.chars().count() > 512
            || request.reason.trim() != request.reason
            || request.reason.chars().any(char::is_control)
            || !revocation_id(&request.revocation_id)
            || ![
                &self.request_sha256,
                &self.operator_certificate,
                &self.delegation_sha256,
            ]
            .into_iter()
            .all(|value| is_digest(value))
        {
            return Err(invalid(
                "unsigned permit does not bind the exact workload and acknowledgment",
            ));
        }
        if request.requested_at == 0
            || request.requested_at > self.issued_at
            || !(self.issued_at..request.expires).contains(&now)
            || request.expires > i64::MAX as u64
        {
            return Err(invalid(
                "unsigned workload permit is outside its validity period",
            ));
        }
        if self.discovery.schema != "fvca-signature-discovery-v1"
            || self.discovery.repository != request.repository
            || self
                .discovery
                .subjects
                .iter()
                .zip([&request.source_index, &request.manifest])
                .any(|(subject, expected)| {
                    &subject.digest != expected
                        || !matches!(subject.referrers_api.status, 200 | 404)
                        || !matches!(subject.referrers_tag.status, 200 | 404)
                        || subject.cosign_signature_tag.status != 404
                        || ![
                            &subject.referrers_api,
                            &subject.referrers_tag,
                            &subject.cosign_signature_tag,
                        ]
                        .into_iter()
                        .all(|probe| is_digest(&probe.response))
                })
        {
            return Err(invalid(
                "unsigned permit lacks complete successful signature discovery",
            ));
        }
        Ok(())
    }
}

pub(crate) fn verify(
    raw: &[u8],
    derivation: &Derivation,
    deployment: &Deployment,
    launch: &Launch,
    trust: &Trust,
    now: u64,
) -> Result<Validity> {
    let mut validity = Validity {
        valid_from: deployment.valid_from,
        expires: deployment.expires,
        permit: None,
    };
    match serde_json::from_slice(raw)? {
        Evidence::PublisherVerified { policy, proof } => {
            let policy = exact_policy(&policy, derivation, launch)?;
            let repository = policy.repository.strip_prefix("docker.io/").map_or_else(
                || policy.repository.clone(),
                |repo| format!("index.docker.io/{repo}"),
            );
            let reference = format!("{repository}@{}", policy.index);
            if deployment.provenance != Provenance::PublisherVerified
                || policy.schema != "fvca-oci-source-v1"
                || policy.permit_authority.is_some()
                || derivation.permit.is_some()
                || ![policy.certificate_identity, policy.certificate_issuer]
                    .into_iter()
                    .all(|name| {
                        name.is_some_and(|value| value.starts_with("https://") && value.len() > 8)
                    })
                || !proof.iter().any(|proof| {
                    proof.critical.kind == "https://sigstore.dev/cosign/sign/v1"
                        && proof.critical.image.digest == deployment.source_index
                        && proof.critical.identity.reference == reference
                })
            {
                return Err(invalid(
                    "publisher evidence differs from the signed-only source policy",
                ));
            }
        }
        Evidence::UnsignedUpstreamApproved {
            policy,
            permit,
            signature,
            authority,
        } => {
            let policy = exact_policy(&policy, derivation, launch)?;
            let pin = trust
                .scope
                .unsigned_permit_authority
                .as_deref()
                .ok_or_else(|| invalid("Guest source policy does not enable unsigned permits"))?;
            let certificate = decode(&authority, SIGNATURE_LIMIT)?;
            let body = decode(&permit, SIGNATURE_LIMIT)?;
            if deployment.provenance != Provenance::UnsignedUpstreamApproved
                || policy.schema != "fvca-oci-explicit-exceptions-v1"
                || policy.certificate_identity.is_some()
                || policy.certificate_issuer.is_some()
                || policy.permit_authority.as_deref() != Some(pin)
                || derivation.permit.as_deref() != Some(digest(&sha256(&body)).as_str())
            {
                return Err(invalid(
                    "unsigned permit differs from its enrolled authority or source policy",
                ));
            }
            let signer = trust.permit_authority(&certificate)?;
            verify_signature(&body, &decode(&signature, SIGNATURE_LIMIT)?, &signer)?;
            let permit: Permit = serde_json::from_slice(&body)?;
            permit.check(derivation, deployment, now)?;
            validity.valid_from = validity.valid_from.max(permit.issued_at);
            validity.expires = validity.expires.min(permit.acknowledgment.expires);
            validity.permit = Some(PermitIdentity {
                guest: permit.acknowledgment.guest,
                service: permit.acknowledgment.service,
                id: permit.acknowledgment.revocation_id,
                permit: digest(&sha256(&body)),
                authority,
                issued_at: permit.issued_at,
                expires: permit.acknowledgment.expires,
            });
        }
    }
    Ok(validity)
}
