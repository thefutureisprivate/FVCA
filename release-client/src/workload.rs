//! Resolve an enrolled, same-data workload transition from a verified TUF channel.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;

use fvca_workload_admission::revocation::NOTICE_LIMIT;
use fvca_workload_admission::{
    ARTIFACT_LIMIT, TRANSITION_MEMBERS, Trust, VerifiedWorkload, verify_transition_offer,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tough::{IntoVec, Repository, TargetName};

use crate::depot::{Depot, METADATA_BYTES};
use crate::repository::{check_target, download, load_repository};
use crate::{Result, invalid, state};

const HEAD_BYTES: u64 = 4096;
const CHECKPOINT: &str = "workload-channel-head.json";
const IMAGE: &str = "candidate/workload.raw";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    schema: String,
    guest: String,
    service: String,
    channel: String,
    tuf_root_sha256: String,
    depot_config_sha256: String,
    max_artifact_bytes: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Head {
    schema: String,
    guest: String,
    service: String,
    channel: String,
    sequence: u64,
    valid_from: i64,
    expires: i64,
    release: Option<Release>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Release {
    from_authorization: String,
    to_authorization: String,
    transition_sha256: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    sequence: u64,
    sha256: String,
}

pub struct Enrollment<'a> {
    pub policy: &'a [u8],
    pub initial_root: Vec<u8>,
    pub depot_config: &'a [u8],
}

pub use fvca_workload_admission::channel::Permit as Prepared;

pub struct Discovery {
    repo: Repository,
    _metadata: tempfile::TempDir,
    head: Head,
    max_artifact_bytes: u64,
    expires: i64,
}

pub struct Refresh {
    repo: Repository,
    metadata: tempfile::TempDir,
    policy: Policy,
    expires: i64,
}

pub struct PermitNotice {
    pub filename: String,
    pub bytes: Vec<u8>,
}

fn hash(input: &[u8]) -> String {
    hex::encode(Sha256::digest(input))
}

fn hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn authorization(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(hex_digest)
}

pub fn admission<T>(value: fvca_workload_admission::Result<T>) -> Result<T> {
    value.map_err(|error| invalid(&error.to_string()).into())
}

impl Policy {
    fn load(enrollment: &Enrollment<'_>, trust: &Trust) -> Result<Self> {
        let body: Self = serde_json::from_slice(enrollment.policy)?;
        if body.schema != "fvca-workload-channel-policy-v1"
            || !trust.identifies(&body.guest, &body.service)
            || !(1..=32).contains(&body.channel.len())
            || !body.channel.as_bytes()[0].is_ascii_lowercase()
            || !body
                .channel
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || body.tuf_root_sha256 != hash(&enrollment.initial_root)
            || body.depot_config_sha256 != hash(enrollment.depot_config)
            || !(1..=ARTIFACT_LIMIT).contains(&body.max_artifact_bytes)
        {
            return Err(invalid("invalid or mismatched workload channel enrollment").into());
        }
        Ok(body)
    }

    fn head_target(&self) -> Result<TargetName> {
        Ok(TargetName::new(format!(
            "fvca-workload.{}.{}.{}.json",
            self.guest, self.service, self.channel,
        ))?)
    }

    fn revocation_prefix(&self) -> String {
        format!(
            "fvca-permit.{}.{}.{}.",
            self.guest, self.service, self.channel
        )
    }
}

impl Head {
    fn validate(&self, policy: &Policy, now: i64) -> Result<()> {
        if self.schema != "fvca-workload-channel-head-v1"
            || self.guest != policy.guest
            || self.service != policy.service
            || self.channel != policy.channel
            || self.sequence == 0
            || self.valid_from <= 0
            || !(self.valid_from..self.expires).contains(&now)
            || self.expires.saturating_sub(self.valid_from) > 604_800
            || self.release.as_ref().is_some_and(|release| {
                !authorization(&release.from_authorization)
                    || !authorization(&release.to_authorization)
                    || release.from_authorization == release.to_authorization
                    || !hex_digest(&release.transition_sha256)
            })
        {
            return Err(invalid("invalid or expired workload channel head").into());
        }
        Ok(())
    }
}

fn remember_head(directory: &Path, head: &Head, bytes: &[u8]) -> Result<()> {
    let path = directory.join(CHECKPOINT);
    let digest = hash(bytes);
    match state::read(&path, HEAD_BYTES) {
        Ok(previous) => {
            let previous: Checkpoint = serde_json::from_slice(&previous)?;
            if !hex_digest(&previous.sha256)
                || head.sequence < previous.sequence
                || (head.sequence == previous.sequence && digest != previous.sha256)
            {
                return Err(invalid("workload channel rollback or conflicting sequence").into());
            }
            if head.sequence == previous.sequence {
                return Ok(());
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut file = tempfile::NamedTempFile::new_in(directory)?;
    serde_json::to_writer(
        &mut file,
        &Checkpoint {
            sequence: head.sequence,
            sha256: digest,
        },
    )?;
    file.flush()?;
    file.as_file().sync_all()?;
    file.persist(path)?;
    File::open(directory)?.sync_all()?;
    Ok(())
}

fn member(release: &Release, name: &str) -> Result<TargetName> {
    Ok(TargetName::new(format!(
        "fvca-workload-{}-{}",
        release.transition_sha256,
        name.strip_prefix("candidate/").unwrap_or(name),
    ))?)
}

fn member_length(repo: &Repository, name: &TargetName, limit: u64) -> Result<u64> {
    let entry = repo
        .targets()
        .signed
        .targets
        .get(name)
        .ok_or_else(|| invalid("workload channel target is missing"))?;
    if !(1..=limit).contains(&entry.length) || entry.hashes.sha256.as_ref().len() != 32 {
        return Err(invalid("workload channel target exceeds its bound").into());
    }
    Ok(entry.length)
}

/// Refresh the pinned repository before resolving notices and the independent workload head.
pub async fn refresh(
    enrollment: Enrollment<'_>,
    trust: &Trust,
    channel_state: &Path,
) -> Result<Refresh> {
    let policy = Policy::load(&enrollment, trust)?;
    state::directory(channel_state)?;
    let depot = Depot::from_config(
        enrollment.depot_config,
        policy.max_artifact_bytes.max(METADATA_BYTES),
    )?;
    let metadata = tempfile::tempdir()?;
    let repo = load_repository(
        depot,
        channel_state,
        enrollment.initial_root,
        metadata.path(),
    )
    .await?;
    let expires = repo
        .root()
        .signed
        .expires
        .as_second()
        .min(repo.timestamp().signed.expires.as_second())
        .min(repo.snapshot().signed.expires.as_second())
        .min(repo.targets().signed.expires.as_second());
    Ok(Refresh {
        repo,
        metadata,
        policy,
        expires,
    })
}

impl Refresh {
    pub fn require_fresh(&self) -> Result<()> {
        if jiff::Timestamp::now().as_second() >= self.expires {
            return Err(invalid("workload repository metadata expired during refresh").into());
        }
        Ok(())
    }

    pub async fn permit_notices(&self, trust: &Trust) -> Result<Vec<PermitNotice>> {
        if !trust.accepts_permit_notices() {
            return Ok(Vec::new());
        }
        let prefix = self.policy.revocation_prefix();
        let mut budget = METADATA_BYTES;
        let mut targets = Vec::new();
        for target in self.repo.targets().signed.targets.keys() {
            let Some(filename) = target.raw().strip_prefix(&prefix) else {
                continue;
            };
            if !filename.split_once('.').is_some_and(|(digest, suffix)| {
                hex_digest(digest) && matches!(suffix, "block.json" | "stop.json")
            }) {
                return Err(invalid("invalid permit revocation target name").into());
            }
            let length = member_length(&self.repo, target, NOTICE_LIMIT)?;
            budget = budget
                .checked_sub(length)
                .ok_or_else(|| invalid("permit revocations exceed their aggregate byte limit"))?;
            targets.push((target, filename));
        }
        let mut notices = Vec::with_capacity(targets.len());
        for (target, filename) in targets {
            self.require_fresh()?;
            let bytes = self
                .repo
                .read_target(target)
                .await?
                .ok_or_else(|| invalid("permit revocation target disappeared"))?
                .into_vec()
                .await?;
            admission(trust.verify_permit_notice(filename, &bytes))?;
            notices.push(PermitNotice {
                filename: filename.to_owned(),
                bytes,
            });
        }
        self.require_fresh()?;
        Ok(notices)
    }

    pub async fn discover(self, channel_state: &Path) -> Result<Discovery> {
        let target = self.policy.head_target()?;
        member_length(&self.repo, &target, HEAD_BYTES)?;
        let bytes = self
            .repo
            .read_target(&target)
            .await?
            .ok_or_else(|| invalid("workload channel head disappeared"))?
            .into_vec()
            .await?;
        let head: Head = serde_json::from_slice(&bytes)?;
        head.validate(&self.policy, jiff::Timestamp::now().as_second())?;
        self.require_fresh()?;
        remember_head(channel_state, &head, &bytes)?;
        Ok(Discovery {
            expires: head.expires.min(self.expires),
            repo: self.repo,
            _metadata: self.metadata,
            head,
            max_artifact_bytes: self.policy.max_artifact_bytes,
        })
    }
}

impl Discovery {
    fn release(&self, mounted: &str) -> Option<&Release> {
        self.head
            .release
            .as_ref()
            .filter(|offer| offer.from_authorization == mounted)
    }

    pub fn grant(&self, mounted: &str) -> Option<&str> {
        self.release(mounted)
            .map(|offer| offer.transition_sha256.as_str())
    }

    fn require_fresh(&self) -> Result<()> {
        if !(self.head.valid_from..self.expires).contains(&jiff::Timestamp::now().as_second()) {
            return Err(invalid("workload channel metadata expired during admission").into());
        }
        Ok(())
    }

    fn verify_offer(
        &self,
        release: &Release,
        trust: &Trust,
        current: impl FnOnce() -> fvca_workload_admission::Result<VerifiedWorkload>,
        directory: &Path,
    ) -> Result<(fvca_workload_admission::VerifiedOffer, TargetName)> {
        let offer = admission(verify_transition_offer(
            current,
            &directory.join("candidate"),
            &directory.join("transition.json"),
            &directory.join("transition.p7s"),
            trust,
        ))?;
        if offer.candidate_authorization() != release.to_authorization
            || offer.approval_digest.strip_prefix("sha256:")
                != Some(release.transition_sha256.as_str())
        {
            return Err(invalid("workload channel offer differs from the signed grant").into());
        }
        let (digest, bytes) = offer.artifact();
        let name = member(release, IMAGE)?;
        let digest = digest
            .strip_prefix("sha256:")
            .ok_or_else(|| invalid("invalid signed artifact digest"))?;
        if check_target(&self.repo, &name, self.max_artifact_bytes, digest)? != bytes {
            return Err(
                invalid("workload artifact length differs from its signed authorization").into(),
            );
        }
        self.require_fresh()?;
        Ok((offer, name))
    }

    fn permit(
        &self,
        release: &Release,
        transition: fvca_workload_admission::VerifiedTransition,
    ) -> Result<Prepared> {
        if transition.current.authorization_digest() != release.from_authorization {
            return Err(
                invalid("workload channel offer no longer matches the current selection").into(),
            );
        }
        let valid_from = (self.head.valid_from as u64).max(transition.valid_from());
        let prepared = Prepared {
            approval: transition.approval_digest,
            from: release.from_authorization.clone(),
            to: release.to_authorization.clone(),
            fresh_until: (self.expires as u64).min(transition.fresh_until),
            valid_from,
        };
        admission(prepared.require_fresh())?;
        Ok(prepared)
    }

    /// Reauthorize the exact staged grant after fetching fresh channel metadata.
    pub fn confirm(
        &self,
        trust: &Trust,
        mounted: &str,
        current: impl FnOnce() -> fvca_workload_admission::Result<VerifiedWorkload>,
        directory: &Path,
    ) -> Result<Prepared> {
        let release = self
            .release(mounted)
            .ok_or_else(|| invalid("no eligible workload offer"))?;
        let (offer, _) = self.verify_offer(release, trust, current, directory)?;
        self.permit(
            release,
            admission(offer.finish(&directory.join("candidate"), trust))?,
        )
    }

    /// Authenticate the candidate records before requesting its raw artifact.
    pub async fn fetch(
        &self,
        trust: &Trust,
        mounted: &str,
        current: impl FnOnce() -> fvca_workload_admission::Result<VerifiedWorkload>,
        output: &Path,
    ) -> Result<Option<Prepared>> {
        if !authorization(mounted) {
            return Err(invalid("invalid committed workload identity").into());
        }
        let Some(release) = self.release(mounted) else {
            return Ok(None);
        };
        state::directory(output)?;
        if fs::read_dir(output)?.next().is_some() {
            return Err(invalid("workload intake expects an empty private destination").into());
        }
        let candidate = output.join("candidate");
        state::staged(&candidate)?;
        for (name, limit) in TRANSITION_MEMBERS
            .into_iter()
            .filter(|(name, _)| *name != IMAGE)
        {
            let target = member(release, name)?;
            let bytes = if name == "transition.json" {
                check_target(&self.repo, &target, limit, &release.transition_sha256)?
            } else {
                member_length(&self.repo, &target, limit)?
            };
            download(&self.repo, &target, &output.join(name), bytes).await?;
        }
        let (offer, target) = self.verify_offer(release, trust, current, output)?;
        let (_, bytes) = offer.artifact();
        let space = rustix::fs::statvfs(output)?;
        if space.f_bavail.saturating_mul(space.f_frsize) < bytes {
            return Err(invalid("insufficient space for the authorized workload artifact").into());
        }
        download(&self.repo, &target, &output.join(IMAGE), bytes).await?;
        let verified = admission(offer.finish(&candidate, trust))?;
        File::open(&candidate)?.sync_all()?;
        File::open(output)?.sync_all()?;
        Ok(Some(self.permit(release, verified)?))
    }
}
