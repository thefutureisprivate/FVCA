//! Admit an exact workload replacement under the existing Guest deployment authority.

use std::path::Path;

use serde::Deserialize;

use super::{
    Result, SIGNATURE_LIMIT, Trust, VerifiedWorkload, check_time, current_time, invalid, is_digest,
    read_bounded, verify_for_source, verify_signature,
};

const TRANSITION_LIMIT: u64 = 4096;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Transition {
    schema: String,
    guest: String,
    service: String,
    from_authorization: String,
    to_authorization: String,
    to_source_policy: String,
    data_compatibility: DataCompatibility,
    valid_from: u64,
    expires: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum DataCompatibility {
    Bidirectional,
}

impl Transition {
    fn check_time(&self, now: u64) -> Result<()> {
        if self.valid_from == 0
            || self.expires > i64::MAX as u64
            || !(self.valid_from..self.expires).contains(&now)
        {
            return Err(invalid(
                "workload transition is outside its validity period",
            ));
        }
        Ok(())
    }

    fn check_scope(&self, trust: &Trust) -> Result<()> {
        if self.schema != "fvca-workload-transition-v1"
            || self.guest != trust.scope.guest
            || self.service != trust.scope.service
            || !is_digest(&self.from_authorization)
            || !is_digest(&self.to_authorization)
            || !is_digest(&self.to_source_policy)
            || self.from_authorization == self.to_authorization
        {
            return Err(invalid(
                "workload transition is outside the enrolled Guest or service scope",
            ));
        }
        self.check_time(current_time()?)
    }
}

pub struct VerifiedTransition {
    pub current: VerifiedWorkload,
    pub candidate: VerifiedWorkload,
    pub fresh_until: u64,
}

fn compatible(current: &VerifiedWorkload, candidate: &VerifiedWorkload) -> Result<()> {
    let from = &current.deployment;
    let to = &candidate.deployment;
    if to.security_epoch < from.security_epoch {
        return Err(invalid(
            "candidate workload would roll back the active security epoch",
        ));
    }
    if current.source.repository != candidate.source.repository
        || current.source.certificate_issuer != candidate.source.certificate_issuer
    {
        return Err(invalid(
            "candidate workload changes the publisher repository or issuer",
        ));
    }
    if from.id_map != to.id_map
        || current.launch.uid != candidate.launch.uid
        || current.launch.gid != candidate.launch.gid
        || current.launch.volumes != candidate.launch.volumes
    {
        return Err(invalid(
            "candidate workload changes the persistent volume or container identity mapping",
        ));
    }
    if from.network != to.network
        || to.limits.memory_bytes > from.limits.memory_bytes
        || to.limits.cpu_percent > from.limits.cpu_percent
        || to.limits.pids > from.limits.pids
    {
        return Err(invalid(
            "candidate workload expands or changes the enrolled network or resource scope",
        ));
    }
    if [&current.launch, &candidate.launch]
        .into_iter()
        .any(|launch| {
            !launch.healthcheck.as_ref().is_some_and(|health| {
                matches!(
                    health.test.first().map(String::as_str),
                    Some("CMD" | "CMD-SHELL")
                )
            })
        })
    {
        return Err(invalid(
            "workload transition requires a declared health check for each release",
        ));
    }
    if current.root_digest == candidate.root_digest && from.launch == to.launch {
        return Err(invalid(
            "workload transition does not change executable or launch bytes",
        ));
    }
    Ok(())
}

/// Verify a signed bidirectionally compatible transition and both endpoint bundles.
///
/// The caller supplies the trusted scope of the current release. The candidate source
/// policy comes from the signed transition. Verify these inputs in private staging
/// with no concurrent writers and retain the returned descriptors through activation.
pub fn verify_transition(
    current: &Path,
    candidate: &Path,
    approval: &Path,
    signature: &Path,
    trust: &Trust,
) -> Result<VerifiedTransition> {
    let body = read_bounded(approval, TRANSITION_LIMIT)?;
    verify_signature(
        &body,
        &read_bounded(signature, SIGNATURE_LIMIT)?,
        &trust.deployment,
    )?;
    let transition: Transition = serde_json::from_slice(&body)?;
    transition.check_scope(trust)?;
    let current = verify_for_source(
        current,
        trust,
        &trust.scope.source_policy,
        Some(&transition.from_authorization),
    )?;
    let candidate = verify_for_source(
        candidate,
        trust,
        &transition.to_source_policy,
        Some(&transition.to_authorization),
    )?;
    match transition.data_compatibility {
        DataCompatibility::Bidirectional => compatible(&current, &candidate)?,
    }
    let now = current_time()?;
    transition.check_time(now)?;
    check_time(&current.deployment, now)?;
    check_time(&candidate.deployment, now)?;
    let fresh_until = transition
        .expires
        .min(current.expires())
        .min(candidate.expires());
    Ok(VerifiedTransition {
        current,
        candidate,
        fresh_until,
    })
}
