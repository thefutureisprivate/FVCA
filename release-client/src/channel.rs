//! Discover exact OS compositions under standing owner and qualification authority.

mod guest;

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;

use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use fvca_trial_authorization::{
    APPROVAL_LIMIT, PROMOTED_RELEASE, PROMOTION_ENROLLMENT, Promotion, RUNNING_CONTEXT, Standing,
    peer_partitions,
};
use jiff::{
    Timestamp,
    tz::{TimeZone, TimeZoneDatabase},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tough::schema::key::Key;
use tough::{IntoVec, Repository, TargetName};

use crate::depot::{CONFIG_BYTES, Depot, EnrolledDepot, METADATA_BYTES};
use crate::{
    MANIFEST_BYTES, Member, Result, Role, Selection, check_target, gpt, handoff, install::Slot,
    invalid, load_repository, stage, state, valid_digest,
};

pub enum Operation {
    Discover,
    PrepareGpt,
    DeliverTrial(Delivery),
    ScheduleGuest(EnrolledDepot),
}

pub enum Delivery {
    Inbox,
    Activate,
    Scheduled {
        depot: EnrolledDepot,
        peer: Option<String>,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    schema: String,
    revision: u64,
    role: Role,
    channel: String,
    enabled: bool,
    valid_from: i64,
    expires: i64,
    tuf_root_sha256: String,
    depot_config_sha256: String,
    qualification_key_ed25519: String,
    compatibility_sha256: String,
    minimum_epoch: u64,
    max_release_bytes: u64,
    max_staged_bytes: u64,
    #[serde(default)]
    maintenance: Window,
    hold: Option<Hold>,
    hypervisor_gpt: Option<gpt::StandingSite>,
    trial_key_ed25519: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Window {
    timezone: String,
    start_minute: u16,
    end_minute: u16,
}

impl Default for Window {
    fn default() -> Self {
        Self {
            timezone: "Europe/Berlin".into(),
            start_minute: 240,
            end_minute: 300,
        }
    }
}

impl Window {
    fn timezone(&self) -> Result<TimeZone> {
        if self.start_minute >= 1440
            || self.end_minute > 1440
            || self.end_minute == self.start_minute
        {
            return Err(invalid("invalid maintenance window").into());
        }
        Ok(TimeZoneDatabase::bundled().get(&self.timezone)?)
    }

    fn contains(&self, now: Timestamp, zone: TimeZone) -> bool {
        let local = now.to_zoned(zone);
        let minute = (i16::from(local.hour()) * 60 + i16::from(local.minute())) as u16;
        if self.start_minute < self.end_minute {
            (self.start_minute..self.end_minute).contains(&minute)
        } else {
            minute >= self.start_minute || minute < self.end_minute
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Hold {
    manifest_sha256: String,
    until: i64,
}

#[derive(Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Active {
    role: Role,
    #[serde(skip_serializing_if = "Option::is_none")]
    slot: Option<Slot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    guest_bundle: Option<String>,
    sequence: u64,
    epoch: u64,
    manifest_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Head {
    schema: String,
    role: Role,
    channel: String,
    sequence: u64,
    valid_from: i64,
    expires: i64,
    compatibility_sha256: String,
    release: Option<Candidate>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Candidate {
    epoch: u64,
    manifest_sha256: String,
    activation: Activation,
    #[serde(skip_serializing_if = "Option::is_none")]
    trial_approval: Option<Member>,
    #[serde(skip_serializing_if = "Option::is_none")]
    promotion_approval: Option<Member>,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "urgency", rename_all = "kebab-case", deny_unknown_fields)]
enum Activation {
    Routine,
    Security { activate_by: i64 },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    sequence: u64,
    sha256: String,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
enum Disposition {
    Disabled,
    NoRelease,
    Current,
    Ready,
    OutsideMaintenance,
    Hold,
    Exhausted,
}

#[derive(Serialize)]
struct Status<'a> {
    schema: &'static str,
    active: &'a Active,
    channel: &'a str,
    disposition: Disposition,
    last_refresh: Option<i64>,
    fresh_until: Option<i64>,
    channel_sequence: Option<u64>,
    candidate: Option<&'a Candidate>,
    staged: Option<String>,
    prepared_inactive_slot: Option<Slot>,
    delivered_trial: Option<String>,
    requested_trial: Option<String>,
    hold_until: Option<i64>,
    security_deadline_missed: bool,
}

fn valid_now(start: i64, end: i64, now: Timestamp) -> bool {
    start > 0 && (start..end).contains(&now.as_second())
}

impl Policy {
    fn validate(&self, now: Timestamp) -> Result<TimeZone> {
        if self.schema != "fvca-os-update-policy-v1"
            || !valid_now(self.valid_from, self.expires, now)
            || self.revision == 0
            || !(1..=32).contains(&self.channel.len())
            || !self
                .channel
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
            || !self.channel.as_bytes()[0].is_ascii_lowercase()
            || !valid_digest(&self.compatibility_sha256)
            || !valid_digest(&self.qualification_key_ed25519)
            || self.minimum_epoch == 0
            || (self.role != Role::Hypervisor && self.hypervisor_gpt.is_some())
            || self.trial_key_ed25519.as_ref().is_some_and(|key| {
                (self.role == Role::Hypervisor && self.hypervisor_gpt.is_none())
                    || !valid_digest(key)
            })
            || !(1..u64::MAX).contains(&self.max_release_bytes)
            || self.max_staged_bytes < self.max_release_bytes
            || self.hold.as_ref().is_some_and(|hold| {
                !valid_digest(&hold.manifest_sha256)
                    || !(self.valid_from..=self.expires).contains(&hold.until)
            })
        {
            return Err(invalid("invalid or expired standing OS update policy").into());
        }
        self.maintenance.timezone()
    }
}

impl Head {
    fn require_scope(&self, policy: &Policy, active: &Active, now: Timestamp) -> Result<()> {
        if self.schema != "fvca-os-channel-v1"
            || self.role != policy.role
            || self.channel != policy.channel
            || self.compatibility_sha256 != policy.compatibility_sha256
            || !valid_now(self.valid_from, self.expires, now)
            || self.expires - self.valid_from > 7 * 86_400
        {
            return Err(invalid(
                "channel authorization is expired or outside standing policy scope",
            )
            .into());
        }
        if self.sequence < active.sequence {
            return Err(invalid("channel sequence is older than the active release").into());
        }
        if let Some(release) = &self.release {
            if release.trial_approval.as_ref().is_some_and(|member| {
                policy.trial_key_ed25519.is_none()
                    || !(65..=trial_limit(policy.role)).contains(&member.bytes)
                    || !valid_digest(&member.sha256)
            }) {
                return Err(
                    invalid("channel trial approval is outside standing policy scope").into(),
                );
            }
            if release.promotion_approval.as_ref().is_some_and(|member| {
                policy.role != Role::Hypervisor
                    || release.trial_approval.is_none()
                    || !(65..=APPROVAL_LIMIT as u64).contains(&member.bytes)
                    || !valid_digest(&member.sha256)
            }) {
                return Err(
                    invalid("channel promotion approval is outside standing policy scope").into(),
                );
            }
            let current = release.manifest_sha256 == active.manifest_sha256;
            if !valid_digest(&release.manifest_sha256)
                || release.epoch < active.epoch
                || (current && release.epoch != active.epoch)
                || (!current && self.sequence == active.sequence)
            {
                return Err(
                    invalid("channel candidate does not advance the active release").into(),
                );
            }
            if let Activation::Security { activate_by } = release.activation
                && !(self.valid_from..self.expires).contains(&activate_by)
            {
                return Err(
                    invalid("security deadline is outside the channel validity interval").into(),
                );
            }
        }
        Ok(())
    }
}

pub(super) fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub(super) fn verify(key: &[u8], bytes: &[u8], signature: &[u8], message: &str) -> Result<()> {
    UnparsedPublicKey::new(&ED25519, key)
        .verify(bytes, signature)
        .map_err(|_| invalid(message).into())
}

fn trial_limit(role: Role) -> u64 {
    match role {
        Role::Hypervisor => APPROVAL_LIMIT as u64,
        Role::ServiceGuest => fvca_trial_authorization::guest::ENVELOPE_LIMIT as u64,
    }
}

async fn boot_envelope(
    repo: &Repository,
    selected: &Selection,
    member: &Member,
    file: &str,
) -> Result<Vec<u8>> {
    let name = selected.name(file)?;
    if check_target(repo, &name, trial_limit(selected.role), &member.sha256)? != member.bytes {
        return Err(invalid("boot envelope length differs from the qualified channel").into());
    }
    let bytes = repo
        .read_target(&name)
        .await?
        .ok_or_else(|| invalid("qualified boot envelope disappeared"))?
        .into_vec()
        .await?;
    if bytes.len() as u64 != member.bytes {
        return Err(invalid("boot envelope is incomplete").into());
    }
    Ok(bytes)
}

pub(super) fn save(path: &Path, name: &str, value: &impl Serialize) -> Result<()> {
    let mut record = tempfile::NamedTempFile::new_in(path)?;
    serde_json::to_writer(&mut record, value)?;
    record.write_all(b"\n")?;
    record.as_file().sync_all()?;
    record.persist(path.join(name))?;
    File::open(path)?.sync_all()?;
    Ok(())
}

fn reconcile_promotion(directory: &Path, active: Active) -> Result<Active> {
    let body = match state::read(Path::new(PROMOTED_RELEASE), APPROVAL_LIMIT as u64) {
        Ok(body) => body,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(active),
        Err(error) => return Err(error.into()),
    };
    let promotion = Promotion::parse(std::str::from_utf8(&body)?)?;
    let stable = if promotion.stable_slot == "a" {
        Slot::A
    } else {
        Slot::B
    };
    let promoted = Active {
        role: Role::Hypervisor,
        slot: Some(stable.other()),
        guest_bundle: None,
        sequence: promotion.candidate_sequence,
        epoch: promotion.trial.candidate_epoch,
        manifest_sha256: promotion.candidate_manifest.into(),
    };
    if active != promoted {
        if active.role != Role::Hypervisor
            || active.slot != Some(stable)
            || active.sequence != promotion.stable_sequence
            || active.epoch != promotion.trial.stable_epoch
            || active.manifest_sha256 != promotion.stable_manifest
        {
            return Err(invalid(
                "standing promotion does not advance the recorded active composition",
            )
            .into());
        }
        save(directory, "active-os-release.json", &promoted)?;
        println!(
            "FVCA_PROMOTED_RELEASE_COMMITTED {}",
            promotion.candidate_manifest
        );
    }
    Ok(promoted)
}

pub(super) fn checkpoint(path: &Path, name: &str, sequence: u64, bytes: &[u8]) -> Result<()> {
    let next = Checkpoint {
        sequence,
        sha256: digest(bytes),
    };
    match state::read(&path.join(name), MANIFEST_BYTES) {
        Ok(previous) => {
            let previous: Checkpoint = serde_json::from_slice(&previous)?;
            if !valid_digest(&previous.sha256)
                || next.sequence < previous.sequence
                || (next.sequence == previous.sequence && next.sha256 != previous.sha256)
            {
                return Err(invalid("signed update sequence rollback or equivocation").into());
            }
            if next.sequence == previous.sequence {
                return Ok(());
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    save(path, name, &next)
}

fn staging_budget(directory: &Path, candidate: &str, policy: &Policy) -> Result<u64> {
    state::staged(directory)?;
    let mut budget = policy.max_staged_bytes;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        state::directory(&entry.path())?;
        if entry.file_name() == candidate {
            continue;
        }
        for file in fs::read_dir(entry.path())? {
            let metadata = file?.path().symlink_metadata()?;
            if !metadata.is_file() {
                return Err(invalid("unexpected file type in OS release staging").into());
            }
            budget = budget
                .checked_sub(metadata.len())
                .ok_or_else(|| invalid("OS release staging exceeds the standing policy quota"))?;
        }
    }
    Ok(budget.min(policy.max_release_bytes))
}

pub(super) async fn target(repo: &Repository, name: String, limit: u64) -> Result<Vec<u8>> {
    let target = TargetName::new(name)?;
    let length = repo
        .targets()
        .signed
        .targets
        .get(&target)
        .map(|target| target.length)
        .filter(|length| (1..=limit).contains(length))
        .ok_or_else(|| invalid("missing or oversized TUF channel target"))?;
    let bytes = repo
        .read_target(&target)
        .await?
        .ok_or_else(|| invalid("authorized TUF channel target disappeared"))?
        .into_vec()
        .await?;
    if bytes.len() as u64 != length {
        return Err(invalid("invalid TUF channel target length").into());
    }
    Ok(bytes)
}

fn eligibility(
    policy: &Policy,
    candidate: &Candidate,
    now: Timestamp,
    zone: TimeZone,
) -> (Disposition, Option<i64>, bool) {
    let security_deadline = match candidate.activation {
        Activation::Routine => None,
        Activation::Security { activate_by } => Some(activate_by),
    };
    let hold = policy
        .hold
        .as_ref()
        .filter(|hold| hold.manifest_sha256 == candidate.manifest_sha256)
        .map(|hold| security_deadline.map_or(hold.until, |deadline| hold.until.min(deadline)))
        .filter(|until| now.as_second() < *until);
    let missed = security_deadline.is_some_and(|deadline| now.as_second() > deadline);
    let disposition = if hold.is_some() {
        Disposition::Hold
    } else if security_deadline.is_some() || policy.maintenance.contains(now, zone) {
        Disposition::Ready
    } else {
        Disposition::OutsideMaintenance
    };
    (disposition, hold, missed)
}

pub async fn discover(
    trusted_root: &Path,
    config: &Path,
    directory: &Path,
    standing_policy: &Path,
    signature: &Path,
    owner_key: &Path,
    operation: Operation,
) -> Result<()> {
    let _lock = state::lock(directory)?;
    let active: Active = serde_json::from_slice(&state::read(
        &directory.join("active-os-release.json"),
        MANIFEST_BYTES,
    )?)?;
    let active = if matches!(
        operation,
        Operation::DeliverTrial(Delivery::Scheduled { .. })
    ) {
        reconcile_promotion(directory, active)?
    } else {
        active
    };
    let owner = state::read(owner_key, 32)?;
    let file = state::read(standing_policy, MANIFEST_BYTES)?;
    verify(
        &owner,
        &file,
        &state::read(signature, 64)?,
        "invalid standing OS update policy signature",
    )?;
    let policy: Policy = serde_json::from_slice(&file)?;
    let zone = policy.validate(Timestamp::now())?;
    if matches!(operation, Operation::ScheduleGuest(_)) && policy.role != Role::ServiceGuest {
        return Err(invalid("scheduled Guest updates require a Service Guest policy").into());
    }
    let qualification = hex::decode(&policy.qualification_key_ed25519)?;
    let trial_key = policy
        .trial_key_ed25519
        .as_ref()
        .map(hex::decode)
        .transpose()?;
    if qualification == owner
        || trial_key
            .as_ref()
            .is_some_and(|key| *key == owner || *key == qualification)
    {
        return Err(
            invalid("owner, qualification and trial authorities must use distinct keys").into(),
        );
    }
    let initial_root = state::read(trusted_root, METADATA_BYTES)?;
    let config = state::read(config, CONFIG_BYTES)?;
    if digest(&initial_root) != policy.tuf_root_sha256
        || digest(&config) != policy.depot_config_sha256
    {
        return Err(invalid("release root or depot differs from standing OS update policy").into());
    }
    if active.role != policy.role || active.sequence == 0 || !valid_digest(&active.manifest_sha256)
    {
        return Err(invalid("active release is outside standing OS update policy").into());
    }
    let installation = match operation {
        Operation::Discover | Operation::ScheduleGuest(_) => None,
        Operation::PrepareGpt | Operation::DeliverTrial(_) => Some(
            policy.hypervisor_gpt.as_ref().zip(active.slot).ok_or_else(|| {
                invalid("this operation requires a signed Hypervisor disk policy and the active slot")
            })?,
        ),
    };
    if matches!(
        operation,
        Operation::DeliverTrial(_) | Operation::ScheduleGuest(_)
    ) && trial_key.is_none()
    {
        return Err(invalid("trial delivery requires a pinned standing trial authority").into());
    }
    checkpoint(
        directory,
        "os-policy-checkpoint.json",
        policy.revision,
        &file,
    )?;
    let active = if matches!(operation, Operation::ScheduleGuest(_)) {
        guest::reconcile(
            directory,
            active,
            trial_key
                .as_deref()
                .expect("validated Guest trial authority"),
        )?
    } else {
        active
    };
    if active.epoch < policy.minimum_epoch || !valid_digest(&active.manifest_sha256) {
        return Err(invalid("observed active release is outside standing OS update policy").into());
    }
    let mut status = Status {
        schema: "fvca-os-update-status-v1",
        active: &active,
        channel: &policy.channel,
        disposition: Disposition::Disabled,
        last_refresh: None,
        fresh_until: None,
        channel_sequence: None,
        candidate: None,
        staged: None,
        prepared_inactive_slot: None,
        delivered_trial: None,
        requested_trial: None,
        hold_until: None,
        security_deadline_missed: false,
    };
    if !policy.enabled {
        return report(directory, &status);
    }

    let scratch = tempfile::Builder::new()
        .prefix(".tuf-")
        .tempdir_in(directory)?;
    let scope = match &operation {
        Operation::DeliverTrial(Delivery::Scheduled { depot, .. }) => {
            Some((depot, Role::Hypervisor.update_state()))
        }
        Operation::ScheduleGuest(depot) => Some((depot, Role::ServiceGuest.update_state())),
        _ => None,
    };
    let depot = Depot::with_scope(&config, policy.max_release_bytes.max(MANIFEST_BYTES), scope)?;
    let repo = load_repository(depot, directory, initial_root, scratch.path()).await?;
    if repo.root().signed.keys.values().any(|key| {
        matches!(key, Key::Ed25519 { keyval, .. } if keyval.public.as_ref() == qualification
            || keyval.public.as_ref() == owner || trial_key.as_deref() == Some(keyval.public.as_ref()))
    }) {
        return Err(invalid("TUF and OS policy authorities must use distinct keys").into());
    }
    let stem = format!("fvca-os-{}-{}", policy.role.prefix(), policy.channel);
    let contents = target(&repo, format!("{stem}.json"), MANIFEST_BYTES).await?;
    let signature = target(&repo, format!("{stem}.sig"), 64).await?;
    verify(
        &qualification,
        &contents,
        &signature,
        "invalid independent channel qualification signature",
    )?;
    let head: Head = serde_json::from_slice(&contents)?;
    let refreshed = Timestamp::now();
    head.require_scope(&policy, &active, refreshed)?;
    let expires = [
        policy.expires,
        head.expires,
        repo.root().signed.expires.as_second(),
        repo.timestamp().signed.expires.as_second(),
        repo.snapshot().signed.expires.as_second(),
        repo.targets().signed.expires.as_second(),
    ]
    .into_iter()
    .min()
    .expect("fixed list of expiry dates");
    if !valid_now(policy.valid_from, expires, refreshed) {
        return Err(invalid("OS update authorization expired during discovery").into());
    }
    checkpoint(
        directory,
        &format!("{stem}-checkpoint.json"),
        head.sequence,
        &contents,
    )?;
    status.last_refresh = Some(refreshed.as_second());
    status.fresh_until = Some(expires);
    status.channel_sequence = Some(head.sequence);
    status.candidate = head.release.as_ref();
    let require_fresh = |now: Timestamp| {
        if (refreshed.as_second()..expires).contains(&now.as_second()) {
            Ok(())
        } else {
            Err(invalid(
                "OS update authorization expired or the clock regressed during discovery",
            ))
        }
    };
    if matches!(operation, Operation::ScheduleGuest(_)) {
        let retain = head
            .release
            .as_ref()
            .filter(|candidate| candidate.manifest_sha256 != active.manifest_sha256)
            .map(|candidate| candidate.manifest_sha256.as_str());
        require_fresh(Timestamp::now())?;
        guest::retire_staging(directory, retain)?;
        if retain.is_none() {
            guest::withdraw(
                &active,
                head.sequence,
                trial_key
                    .as_deref()
                    .expect("validated Guest trial authority"),
                &|| Ok(require_fresh(Timestamp::now())?),
            )?;
        }
    }
    let mut request_result = Ok(());
    status.disposition = match &head.release {
        None => Disposition::NoRelease,
        Some(candidate) if candidate.manifest_sha256 == active.manifest_sha256 => {
            Disposition::Current
        }
        Some(candidate) => {
            let staging = directory.join("staged");
            let budget = staging_budget(&staging, &candidate.manifest_sha256, &policy)?;
            if budget == 0 {
                return Err(invalid("OS release staging quota is exhausted").into());
            }
            let selection = Selection {
                role: policy.role,
                epoch: candidate.epoch,
                minimum_epoch: policy.minimum_epoch,
                manifest_sha256: candidate.manifest_sha256.clone(),
                max_release_bytes: budget,
            };
            let staged = stage(&repo, &selection, &staging).await?;
            status.staged = Some(candidate.manifest_sha256.clone());
            let now = Timestamp::now();
            require_fresh(now)?;
            let (mut disposition, hold, missed) =
                eligibility(&policy, candidate, now, zone.clone());
            let eligible = || {
                let now = Timestamp::now();
                require_fresh(now)?;
                if !matches!(
                    eligibility(&policy, candidate, now, zone.clone()).0,
                    Disposition::Ready
                ) {
                    return Err(invalid(
                        "release is no longer eligible for preparation or trial delivery",
                    )
                    .into());
                }
                Ok(())
            };
            if let Some((site, slot)) = installation
                && matches!(disposition, Disposition::Ready)
            {
                let active_slot = (slot, active.epoch, active.manifest_sha256.as_str());
                match &operation {
                    Operation::DeliverTrial(delivery) => {
                        let member = candidate.trial_approval.as_ref().ok_or_else(|| {
                            invalid("qualified channel does not authorize a trial envelope")
                        })?;
                        let envelope =
                            boot_envelope(&repo, &selection, member, "boot-trial.bin").await?;
                        let (proof, body) = envelope
                            .split_first_chunk::<64>()
                            .ok_or_else(|| invalid("truncated standing trial envelope"))?;
                        let key = trial_key
                            .as_deref()
                            .ok_or_else(|| invalid("missing pinned trial authority"))?;
                        verify(
                            key,
                            body,
                            proof,
                            "invalid independent standing trial signature",
                        )?;
                        let approval = Standing::parse(std::str::from_utf8(body)?)?;
                        let promotion = if let (Delivery::Scheduled { .. }, Some(member)) =
                            (delivery, &candidate.promotion_approval)
                        {
                            let authority = state::read(Path::new(PROMOTION_ENROLLMENT), 32)?;
                            if authority == owner || authority == qualification || authority == key
                                || repo.root().signed.keys.values().any(|entry| {
                                    matches!(entry, Key::Ed25519 { keyval, .. } if keyval.public.as_ref() == authority)
                                })
                            {
                                return Err(invalid("the standing promotion authority must be independent").into());
                            }
                            let packet =
                                boot_envelope(&repo, &selection, member, "boot-promotion.bin")
                                    .await?;
                            let (signature, body) = packet
                                .split_first_chunk::<64>()
                                .ok_or_else(|| invalid("truncated standing promotion approval"))?;
                            verify(
                                &authority,
                                body,
                                signature,
                                "invalid standing promotion signature",
                            )?;
                            let promote = Promotion::parse(std::str::from_utf8(body)?)?;
                            promote.matches_trial(&envelope)?;
                            if promote.stable_slot
                                != match slot {
                                    Slot::A => "a",
                                    Slot::B => "b",
                                }
                                || promote.stable_sequence != active.sequence
                                || promote.candidate_sequence != head.sequence
                                || promote.stable_manifest != active.manifest_sha256
                                || promote.candidate_manifest != selection.manifest_sha256
                            {
                                return Err(invalid("standing promotion differs from the release channel transition").into());
                            }
                            Some(packet)
                        } else {
                            None
                        };
                        let authorize = || {
                            eligible()?;
                            approval.require_fresh(Timestamp::now().as_second().try_into()?)?;
                            Ok(())
                        };
                        authorize()?;
                        let peer = if let Delivery::Scheduled { peer, .. } = delivery {
                            approval.require_running_context(
                                key,
                                &state::read(Path::new(RUNNING_CONTEXT), APPROVAL_LIMIT as u64)?,
                            )?;
                            peer.as_deref().map(peer_partitions).transpose()?
                        } else {
                            None
                        };
                        let lease = peer.as_ref().map(|_| handoff::lock_install()).transpose()?;
                        let transaction = approval.authorization.trial.transaction;
                        if let Some(peer) = peer
                            && !handoff::check_install(transaction, &envelope)?
                        {
                            let authorize_install = || {
                                authorize()?;
                                if handoff::check_install(transaction, &envelope)? {
                                    return Err(invalid(
                                        "trial was published during live preparation",
                                    )
                                    .into());
                                }
                                Ok(())
                            };
                            site.install(
                                active_slot,
                                &selection,
                                &staged,
                                directory,
                                &authorize_install,
                                Some(gpt::LiveInstall {
                                    peer,
                                    approval: &approval,
                                    trial_key: key,
                                }),
                            )?;
                        } else {
                            site.verify_prepared(
                                active_slot,
                                &selection,
                                &staged,
                                scratch.path(),
                                &approval,
                                key,
                            )?;
                        }
                        handoff::publish(
                            &envelope,
                            promotion.as_deref().map(|packet| (transaction, packet)),
                            &authorize,
                        )?;
                        drop(lease);
                        status.delivered_trial = Some(transaction.into());
                        if !matches!(delivery, Delivery::Inbox) {
                            request_result =
                                authorize().and_then(|()| handoff::request_activation());
                            if request_result.is_ok() {
                                status.requested_trial.clone_from(&status.delivered_trial);
                            }
                        }
                    }
                    Operation::PrepareGpt => {
                        site.install(active_slot, &selection, &staged, directory, &eligible, None)?
                    }
                    Operation::Discover | Operation::ScheduleGuest(_) => {
                        unreachable!("this operation has no GPT installation policy")
                    }
                }
                status.prepared_inactive_slot = Some(slot.other());
            }
            if matches!(operation, Operation::ScheduleGuest(_))
                && matches!(disposition, Disposition::Ready)
            {
                let member = candidate.trial_approval.as_ref().ok_or_else(|| {
                    invalid("qualified channel does not authorize a Guest trial envelope")
                })?;
                let envelope = boot_envelope(&repo, &selection, member, "guest-trial.bin").await?;
                status.delivered_trial = guest::deliver(
                    guest::Delivery {
                        active: &active,
                        selection: &selection,
                        sequence: head.sequence,
                        staged: &staged,
                        envelope: &envelope,
                        key: trial_key
                            .as_deref()
                            .expect("validated Guest trial authority"),
                    },
                    &eligible,
                )?;
                if status.delivered_trial.is_some() {
                    request_result = eligible().and_then(|()| guest::request_activation());
                    if request_result.is_ok() {
                        status.requested_trial.clone_from(&status.delivered_trial);
                    }
                } else {
                    disposition = Disposition::Exhausted;
                }
            }
            status.hold_until = hold;
            status.security_deadline_missed = missed;
            disposition
        }
    };
    require_fresh(Timestamp::now())?;
    report(directory, &status)?;
    request_result
}

fn report(directory: &Path, status: &Status<'_>) -> Result<()> {
    save(directory, "os-update-status.json", status)?;
    println!("{}", serde_json::to_string(status)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn berlin_window_follows_daylight_saving() -> Result<()> {
        let window = Window::default();
        let zone = window.timezone()?;
        for (stamp, expected) in [
            ("2026-03-28T02:59:59Z", false),
            ("2026-03-28T03:00:00Z", true),
            ("2026-03-29T01:59:59Z", false),
            ("2026-03-29T02:00:00Z", true),
            ("2026-03-29T03:00:00Z", false),
            ("2026-10-24T02:00:00Z", true),
            ("2026-10-25T02:59:59Z", false),
            ("2026-10-25T03:00:00Z", true),
            ("2026-10-25T04:00:00Z", false),
        ] {
            assert_eq!(
                window.contains(stamp.parse()?, zone.clone()),
                expected,
                "{stamp}"
            );
        }
        Ok(())
    }
}
