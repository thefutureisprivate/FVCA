//! Prepare and package an independently signed OS channel head on a review workstation.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;

use fvca_trial_authorization::guest_config::CHANGE_LIMIT;
use rustix::fs::{CWD, RenameFlags, renameat_with};
use serde::Deserialize;
use tough::schema::{Root, Signed};

use super::{
    ACTIVE_RELEASE, APPROVAL_LIMIT, Activation, Active, Candidate, Head, Key, MANIFEST_BYTES,
    METADATA_BYTES, Member, Policy, Promotion, Result, Role, Selection, Slot, Standing, Timestamp,
    channel_stem, digest, gpt, guest, guest_configuration, invalid, state, trial_limit,
    valid_digest, verify,
};
use crate::{MANIFEST, Manifest, verify_member};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    sequence: u64,
    valid_from: i64,
    expires: i64,
    #[serde(deserialize_with = "Deserialize::deserialize")]
    release: Option<RequestedRelease>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestedRelease {
    manifest_sha256: String,
    activation: Activation,
}

struct Review {
    head: Head,
    qualification: Vec<u8>,
    attachments: Vec<(String, Vec<u8>)>,
}

fn approved_file(package: &Path, selected: &Selection, name: &str, hash: &str) -> Result<File> {
    let target = selected.name(name)?;
    Ok(state::open_regular(
        &package
            .join("targets")
            .join(format!("{hash}.{}", target.raw())),
    )?)
}

fn optional(approvals: &Path, filename: &str, limit: u64) -> Result<Option<Vec<u8>>> {
    match state::read(&approvals.join(filename), limit) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn member(bytes: &[u8]) -> Member {
    Member {
        bytes: bytes.len() as u64,
        sha256: digest(bytes),
    }
}

fn signed_body<'a>(key: &[u8], envelope: &'a [u8]) -> Result<&'a str> {
    let (signature, body) = envelope
        .split_first_chunk::<64>()
        .ok_or_else(|| invalid("truncated channel attachment"))?;
    verify(
        key,
        body,
        signature,
        "invalid independent channel attachment signature",
    )?;
    Ok(std::str::from_utf8(body)?)
}

struct Scope<'a> {
    directory: &'a Path,
    policy: Policy,
    active: Active,
    qualification: Vec<u8>,
    trial: Option<Vec<u8>>,
    used_keys: Vec<Vec<u8>>,
}

impl<'a> Scope<'a> {
    fn read(directory: &'a Path, now: Timestamp) -> Result<Self> {
        state::directory(directory)?;
        let owner = state::read(&directory.join("owner.public"), 32)?;
        let bytes = state::read(&directory.join("policy.json"), MANIFEST_BYTES)?;
        verify(
            &owner,
            &bytes,
            &state::read(&directory.join("policy.sig"), 64)?,
            "invalid standing OS update policy signature",
        )?;
        let policy: Policy = serde_json::from_slice(&bytes)?;
        policy.validate(now)?;
        let (qualification, trial) = policy.authorities(&owner)?;
        let active: Active = serde_json::from_slice(&state::read(
            &directory.join(ACTIVE_RELEASE),
            MANIFEST_BYTES,
        )?)?;
        if active.role != policy.role
            || active.sequence == 0
            || active.epoch < policy.minimum_epoch
            || !valid_digest(&active.manifest_sha256)
        {
            return Err(invalid("active release is outside standing OS update policy").into());
        }
        let bytes = state::read(&directory.join("trusted-root.json"), METADATA_BYTES)?;
        if digest(&bytes) != policy.tuf_root_sha256 {
            return Err(invalid("release root differs from standing OS update policy").into());
        }
        let root: Signed<Root> = serde_json::from_slice(&bytes)?;
        let mut used_keys = vec![owner, qualification.clone()];
        used_keys.extend(trial.iter().cloned());
        for key in root.signed.keys.values() {
            if let Key::Ed25519 { keyval, .. } = key {
                if used_keys
                    .iter()
                    .any(|key| key.as_slice() == keyval.public.as_ref())
                {
                    return Err(
                        invalid("TUF and OS channel authorities must use distinct keys").into(),
                    );
                }
            }
        }
        used_keys.extend(root.signed.keys.into_values().filter_map(|key| match key {
            Key::Ed25519 { keyval, .. } => Some(keyval.public.as_ref().to_vec()),
            _ => None,
        }));
        Ok(Self {
            directory,
            policy,
            active,
            qualification,
            trial,
            used_keys,
        })
    }

    fn attachment_key(&mut self, file: &str) -> Result<[u8; 32]> {
        let key = state::read(&self.directory.join(file), 32)?;
        if self.used_keys.contains(&key) {
            return Err(invalid("channel attachment authorities must use distinct keys").into());
        }
        let result = key.as_slice().try_into()?;
        self.used_keys.push(key);
        Ok(result)
    }

    fn candidate(
        &mut self,
        requested: RequestedRelease,
        package: &Path,
        approvals: &Path,
        sequence: u64,
    ) -> Result<(Candidate, Vec<(String, Vec<u8>)>)> {
        let selected: Selection = serde_json::from_slice(&state::read(
            &package.join("selection.json"),
            MANIFEST_BYTES,
        )?)?;
        selected.validate()?;
        if selected.role != self.policy.role
            || selected.epoch < self.policy.minimum_epoch
            || selected.manifest_sha256 != requested.manifest_sha256
        {
            return Err(invalid(
                "prepared release differs from the requested role, epoch or manifest",
            )
            .into());
        }
        let mut bytes = Vec::new();
        approved_file(package, &selected, MANIFEST, &selected.manifest_sha256)?
            .take(MANIFEST_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MANIFEST_BYTES || digest(&bytes) != selected.manifest_sha256 {
            return Err(
                invalid("prepared release manifest differs from the requested digest").into(),
            );
        }
        let manifest: Manifest = serde_json::from_slice(&bytes)?;
        let members = manifest.members(selected.role, selected.epoch)?;
        let mut budget = bytes.len() as u64;
        let mut boot = None;
        let mut guest_image = None;
        for (name, member) in &members {
            budget = budget
                .checked_add(member.bytes)
                .filter(|&size| size <= self.policy.max_release_bytes)
                .ok_or_else(|| {
                    invalid("prepared release exceeds the standing policy staging budget")
                })?;
            let file = approved_file(package, &selected, name, &member.sha256)?;
            verify_member(file.try_clone()?, member)?;
            if *name == "boot.raw" {
                boot = Some(file);
            } else if *name == "guest-boot.raw" && selected.role == Role::ServiceGuest {
                guest_image = Some(file);
            }
        }
        if selected.max_release_bytes != budget {
            return Err(invalid(
                "prepared release selection differs from the complete target lengths",
            )
            .into());
        }

        let trial_name = match selected.role {
            Role::Hypervisor => "boot-trial.bin",
            Role::ServiceGuest => "guest-trial.bin",
        };
        let trial = optional(approvals, trial_name, trial_limit(selected.role))?;
        let promotion = optional(approvals, "boot-promotion.bin", APPROVAL_LIMIT as u64)?;
        let change = optional(
            approvals,
            "guest-configuration-change.bin",
            CHANGE_LIMIT as u64,
        )?;
        if (promotion.is_some() && (selected.role != Role::Hypervisor || trial.is_none()))
            || (change.is_some() && promotion.is_none())
        {
            return Err(invalid(
                "channel promotion or configuration lacks its required Host trial approvals",
            )
            .into());
        }
        if let Some(envelope) = &trial {
            let now = Timestamp::now().as_second().try_into()?;
            let key = self
                .trial
                .clone()
                .ok_or_else(|| invalid("standing policy lacks a trial authority"))?;
            if let Some(boot) = boot {
                let approval = Standing::parse(signed_body(&key, envelope)?)?;
                requested.activation.require_trial_deadline(&approval)?;
                approval.require_fresh(now)?;
                approval.require_running_context(
                    &key,
                    &state::read(
                        &self.directory.join("running-context"),
                        APPROVAL_LIMIT as u64,
                    )?,
                )?;
                if let Some(packet) = &promotion {
                    let authority = self.attachment_key("promotion.public")?;
                    let grant = Promotion::parse(signed_body(&authority, packet)?)?;
                    grant.matches_trial(envelope)?;
                    let slot = match self.active.slot {
                        Some(Slot::A) => "a",
                        Some(Slot::B) => "b",
                        None => {
                            return Err(invalid(
                                "publication scope lacks the active Hypervisor slot",
                            )
                            .into());
                        }
                    };
                    if grant.stable_slot != slot
                        || grant.stable_sequence != self.active.sequence
                        || grant.candidate_sequence != sequence
                        || grant.stable_manifest != self.active.manifest_sha256
                        || grant.candidate_manifest != selected.manifest_sha256
                    {
                        return Err(invalid(
                            "standing promotion differs from the release channel transition",
                        )
                        .into());
                    }
                }
                let change_grant = change
                    .as_ref()
                    .map(|packet| {
                        guest_configuration::authorize(
                            packet.clone(),
                            envelope,
                            self.attachment_key("guest-configuration.public")?,
                        )
                    })
                    .transpose()?;
                self.policy
                    .hypervisor_gpt
                    .as_ref()
                    .ok_or_else(|| invalid("standing policy lacks a Hypervisor disk profile"))?
                    .verify_channel_candidate(
                        &boot,
                        &self.directory.join("secure-boot.pem"),
                        (self.active.epoch, selected.epoch),
                        &approval,
                        &key,
                        change_grant.as_ref(),
                    )?;
            } else {
                let approval = guest::signed(&key, envelope)?;
                approval.require_fresh(now)?;
                let image = members[0].1;
                if approval.stable_epoch != self.active.epoch
                    || approval.candidate_epoch != selected.epoch
                    || self.active.guest_bundle.as_deref() != Some(approval.stable)
                    || approval.image_bytes != image.bytes
                    || approval.image_digest != image.sha256
                {
                    return Err(invalid(
                        "Guest trial differs from the exact qualified release transition",
                    )
                    .into());
                }
                let image = guest_image.ok_or_else(|| {
                    invalid("qualified release lacks the packed Guest boot image")
                })?;
                gpt::require_guest_trial_root(&image, approval.selection.bundle)?;
            }
        }
        let candidate = Candidate {
            epoch: selected.epoch,
            manifest_sha256: selected.manifest_sha256.clone(),
            activation: requested.activation,
            trial_approval: trial.as_deref().map(member),
            promotion_approval: promotion.as_deref().map(member),
            guest_configuration_change: change.as_deref().map(member),
        };
        let attachments = [
            (trial_name, trial),
            ("boot-promotion.bin", promotion),
            ("guest-configuration-change.bin", change),
        ]
        .into_iter()
        .filter_map(|(name, bytes)| bytes.map(|bytes| (name, bytes)))
        .map(|(name, bytes)| Ok((selected.name(name)?.raw().to_owned(), bytes)))
        .collect::<Result<_>>()?;
        Ok((candidate, attachments))
    }
}

fn review(scope: &Path, request: &Path, package: &Path, approvals: &Path) -> Result<Review> {
    let now = Timestamp::now();
    let mut scope = Scope::read(scope, now)?;
    let requested: Request = serde_json::from_slice(&state::read(request, MANIFEST_BYTES)?)?;
    if requested.sequence <= scope.active.sequence {
        return Err(invalid("a new channel head must advance the observed active sequence").into());
    }
    let (release, attachments) = match requested.release {
        Some(release) => {
            let (candidate, attachments) =
                scope.candidate(release, package, approvals, requested.sequence)?;
            (Some(candidate), attachments)
        }
        None => (None, Vec::new()),
    };
    let head = Head {
        schema: "fvca-os-channel-v1".into(),
        role: scope.policy.role,
        channel: scope.policy.channel.clone(),
        sequence: requested.sequence,
        valid_from: requested.valid_from,
        expires: requested.expires,
        compatibility_sha256: scope.policy.compatibility_sha256.clone(),
        release,
    };
    scope.policy.validate(Timestamp::now())?;
    head.require_scope(&scope.policy, &scope.active, Timestamp::now())?;
    Ok(Review {
        head,
        qualification: scope.qualification,
        attachments,
    })
}

pub fn execute(
    scope: &Path,
    request: &Path,
    package: &Path,
    approvals: &Path,
    signed: Option<(&Path, &Path)>,
) -> Result<()> {
    let Review {
        head,
        qualification,
        mut attachments,
    } = review(scope, request, package, approvals)?;
    let mut document = serde_json::to_vec(&head)?;
    document.push(b'\n');
    let Some((signature, output)) = signed else {
        io::stdout().lock().write_all(&document)?;
        return Ok(());
    };
    let signature = state::read(signature, 64)?;
    verify(
        &qualification,
        &document,
        &signature,
        "invalid independent channel qualification signature",
    )?;
    let stem = channel_stem(head.role, &head.channel);
    attachments.extend([
        (format!("{stem}.json"), document),
        (format!("{stem}.sig"), signature),
    ]);
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let scratch = tempfile::tempdir_in(parent)?;
    let ready = scratch.path().join("channel");
    state::staged(&ready)?;
    let targets = ready.join("targets");
    fs::create_dir(&targets)?;
    let mut records = BTreeMap::new();
    for (name, bytes) in attachments {
        let hash = digest(&bytes);
        fs::write(targets.join(format!("{hash}.{name}")), &bytes)?;
        records.insert(
            name,
            serde_json::json!({"length": bytes.len(), "hashes": {"sha256": hash}}),
        );
    }
    fs::write(
        ready.join("target-records.json"),
        serde_json::to_vec(&records)?,
    )?;
    renameat_with(CWD, &ready, CWD, output, RenameFlags::NOREPLACE)?;
    println!("FVCA_OS_CHANNEL_TARGETS_PREPARED {stem} {}", head.sequence);
    Ok(())
}
