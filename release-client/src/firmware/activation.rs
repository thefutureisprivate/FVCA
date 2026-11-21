//! Reconcile interrupted activation before renewing or retiring firmware staging.

use std::fs::File;
use std::io::{self, Read};

use fvca_trial_authorization::firmware::{
    ACTIVATION, DRAIN_RECEIPT, RUN_DIRECTORY, activation_pending,
};
use rustix::fs::{self, OFlags};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};

use super::{ARCHIVE, Esrt, boot_id, capsule, dispatch, lower_hex, result, uuid};
use crate::{Result, handoff, invalid, state, valid_digest};

const SCHEMA: &str = "fvca-firmware-activation-v2";
const LIMIT: u64 = 1024;
const RESULT_SCHEMA: &str = "fvca-firmware-activation-result-v1";
const RESULT_LIMIT: u64 = 8192;
const VERIFIED_SUCCESS: &str = "verified-success";
const PRIVATE_READ: OFlags = OFlags::RDONLY.union(OFlags::NONBLOCK).union(OFlags::NOCTTY);
const DIRECTORY: OFlags = OFlags::RDONLY.union(OFlags::DIRECTORY);

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Phase {
    Draining,
    Flashing,
    RebootPending,
    PowerTransitionPending,
    OutcomeUnknown,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Activation {
    schema: String,
    pub(super) transaction: String,
    pub(super) boot_id: String,
    pub(super) offer_sha256: String,
    pub(super) device_id: String,
    phase: Phase,
    guest_was_active: bool,
    pub(super) mains_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) queued: Option<capsule::QueuedCapsule>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) esrt_before: Option<Esrt>,
}

impl Activation {
    fn read(file: File) -> Result<Self> {
        let mut bytes = Vec::new();
        file.take(LIMIT + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > LIMIT {
            return Err(invalid("firmware activation record exceeds its size bound").into());
        }
        let record: Self = serde_json::from_slice(&bytes)?;
        if record.schema != SCHEMA
            || !uuid(&record.transaction)
            || !uuid(&record.boot_id)
            || !valid_digest(&record.offer_sha256)
            || !lower_hex(&record.device_id, 40)
            || (record.phase == Phase::RebootPending) != record.queued.is_some()
            || record.queued.as_ref().is_some_and(|queued| !queued.valid())
        {
            return Err(invalid("invalid firmware activation identity").into());
        }
        Ok(record)
    }

    fn reconcile(mut self, pool: &File) -> Result<Self> {
        if self.phase == Phase::Flashing {
            // An updater which still owns the lifecycle lease cannot reach this
            // observation. The device may nevertheless be completing a write.
            self.phase = Phase::OutcomeUnknown;
            handoff::replace_record(pool, ACTIVATION, &serde_json::to_vec(&self)?, &|| Ok(()))?;
        }
        Ok(self)
    }

    pub(super) fn disposition(&self) -> &'static str {
        match self.phase {
            Phase::Draining => "draining",
            Phase::Flashing => "flashing",
            Phase::RebootPending => "reboot-pending",
            Phase::PowerTransitionPending => "power-transition-pending",
            Phase::OutcomeUnknown => "outcome-unknown",
        }
    }

    pub(super) fn writer_operation(pool: &File, current_boot: &str) -> Result<Self> {
        let record = pending(pool)?.ok_or_else(|| invalid("firmware activation is missing"))?;
        record.require_writer_boot(current_boot)?;
        Ok(record)
    }

    fn require_writer_boot(&self, current_boot: &str) -> Result<()> {
        if !matches!(self.phase, Phase::Draining | Phase::Flashing) || self.boot_id != current_boot
        {
            return Err(
                invalid("firmware writer requires an active operation on this boot").into(),
            );
        }
        Ok(())
    }

    pub(super) fn begin(
        pool: &File,
        offer_sha256: &str,
        device_id: &str,
        esrt: Esrt,
        guest_was_active: bool,
    ) -> Result<Self> {
        let raw = state::read(std::path::Path::new("/proc/sys/kernel/random/uuid"), 37)?;
        let transaction = std::str::from_utf8(&raw)?
            .strip_suffix('\n')
            .filter(|id| uuid(id))
            .ok_or_else(|| invalid("invalid Linux firmware transaction ID"))?;
        let record = Self {
            schema: SCHEMA.into(),
            transaction: transaction.into(),
            boot_id: boot_id()?,
            offer_sha256: offer_sha256.into(),
            device_id: device_id.into(),
            phase: Phase::Draining,
            guest_was_active,
            mains_required: false,
            queued: None,
            esrt_before: Some(esrt),
        };
        handoff::publish_record(pool, ACTIVATION, &serde_json::to_vec(&record)?, &|| Ok(()))?;
        Ok(record)
    }

    pub(super) fn flash(
        &mut self,
        pool: &File,
        mains_required: bool,
        authorize: &dyn Fn() -> Result<()>,
    ) -> Result<()> {
        let flashing = Self {
            phase: Phase::Flashing,
            mains_required,
            ..self.clone()
        };
        handoff::replace_record(pool, ACTIVATION, &serde_json::to_vec(&flashing)?, authorize)?;
        *self = flashing;
        Ok(())
    }

    pub(super) fn mark_queued(
        &mut self,
        pool: &File,
        queued: capsule::QueuedCapsule,
    ) -> Result<()> {
        self.phase = Phase::RebootPending;
        self.queued = Some(queued);
        handoff::replace_record(pool, ACTIVATION, &serde_json::to_vec(self)?, &|| Ok(()))
    }

    pub(super) fn mark_uncertain(&mut self, pool: &File) -> Result<()> {
        self.phase = Phase::OutcomeUnknown;
        handoff::replace_record(pool, ACTIVATION, &serde_json::to_vec(self)?, &|| Ok(()))
    }

    pub(super) fn is_draining(&self) -> bool {
        self.phase == Phase::Draining
    }

    pub(super) fn cancel_drain(&self, pool: &File) -> Result<()> {
        if self.phase != Phase::Draining || pending(pool)?.as_ref() != Some(self) {
            return Err(invalid("firmware drain lost custody of its activation record").into());
        }
        super::boot::require_enforced_boot()?;
        let current_boot = boot_id()?;
        if current_boot == self.boot_id {
            dispatch::restore_inventory()?;
        }
        capsule::verify_ordinary_boot()?;
        capsule::require_clear_queue()?;
        if current_boot == self.boot_id {
            let receipt = std::path::Path::new(RUN_DIRECTORY).join(DRAIN_RECEIPT);
            match std::fs::remove_file(receipt) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        let name = format!("activation-aborted-{}.json", self.transaction);
        let bytes = serde_json::to_vec(&self)?;
        match handoff::open_child(pool, &name, PRIVATE_READ) {
            Ok(file) => {
                handoff::private_file(&file)?;
                if Self::read(file)? != *self {
                    return Err(invalid(
                        "aborted firmware drain receipt differs from its operation",
                    )
                    .into());
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                handoff::publish_record(pool, &name, &bytes, &|| Ok(()))?
            }
            Err(error) => return Err(error.into()),
        }
        if self.guest_was_active && current_boot == self.boot_id {
            dispatch::resume_guest()?;
        }
        fs::unlinkat(pool, ACTIVATION, fs::AtFlags::empty())?;
        pool.sync_all()?;
        Ok(())
    }
}

pub(super) fn pending(pool: &File) -> Result<Option<Activation>> {
    let file = match handoff::open_child(pool, ACTIVATION, PRIVATE_READ) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    handoff::private_file(&file)?;
    Ok(Some(Activation::read(file)?))
}

pub(super) struct Recovery {
    pub(super) activation: Activation,
    pub(super) evidence: result::Evidence,
    pub(super) completion_blocker: Option<String>,
}

impl Recovery {
    pub(super) fn disposition(&self) -> &'static str {
        if self.completion_blocker.is_none() {
            match self.activation.phase {
                Phase::Draining => "failed",
                _ => VERIFIED_SUCCESS,
            }
        } else {
            self.activation.disposition()
        }
    }
}

pub(super) fn recover(pool: &File) -> Result<Option<Recovery>> {
    if !activation_pending()? {
        return Ok(None);
    }
    let _lease = handoff::lock_install()?;
    let activation = pending(pool)?
        .ok_or_else(|| invalid("firmware activation disappeared while acquiring its lease"))?
        .reconcile(pool)?;
    let evidence = result::inspect(pool, &activation);
    let completion_blocker = if activation.phase == Phase::Draining {
        activation
            .cancel_drain(pool)
            .err()
            .map(|error| error.to_string())
    } else if activation.phase == Phase::RebootPending {
        if matches!(&evidence, result::Evidence::SameBoot { .. }) {
            let request = dispatch::queue_reboot(&activation);
            Some(match request {
                Ok(()) => "the requested firmware reboot has not completed".into(),
                Err(error) => error.to_string(),
            })
        } else {
            match evidence.verify_completion(pool, &activation) {
                Ok(()) => {
                    commit_verified(pool, &activation, &serde_json::to_value(&evidence)?)?;
                    None
                }
                Err(error) => Some(error.to_string()),
            }
        }
    } else {
        Some("the recorded activation phase requires device-specific recovery".into())
    };
    Ok(Some(Recovery {
        activation,
        evidence,
        completion_blocker,
    }))
}

#[derive(Serialize)]
struct VerifiedResult<'a> {
    schema: &'static str,
    disposition: &'static str,
    activation: &'a Activation,
    evidence: &'a serde_json::Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedResult {
    schema: String,
    disposition: String,
    activation: Activation,
    evidence: serde_json::Value,
}

fn commit_verified(
    pool: &File,
    activation: &Activation,
    evidence: &serde_json::Value,
) -> Result<()> {
    let name = format!("activation-result-{}.json", activation.transaction);
    match handoff::open_child(pool, &name, PRIVATE_READ) {
        Ok(file) => {
            handoff::private_file(&file)?;
            let mut bytes = Vec::new();
            (&file).take(RESULT_LIMIT + 1).read_to_end(&mut bytes)?;
            if bytes.len() as u64 > RESULT_LIMIT {
                return Err(invalid("saved firmware result exceeds its size bound").into());
            }
            let mut saved: SavedResult = serde_json::from_slice(&bytes)?;
            // An interrupted commit can be reconciled from a later qualified
            // boot. Keep the original receipt and compare every other fact.
            let boot = saved
                .evidence
                .get_mut("boot_id")
                .filter(|value| {
                    value
                        .as_str()
                        .is_some_and(|id| uuid(id) && id != activation.boot_id)
                })
                .ok_or_else(|| {
                    invalid("saved firmware result lacks a distinct verification boot")
                })?;
            *boot = evidence["boot_id"].clone();
            if saved.schema != RESULT_SCHEMA
                || saved.disposition != VERIFIED_SUCCESS
                || saved.activation != *activation
                || saved.evidence != *evidence
            {
                return Err(
                    invalid("saved firmware result differs from the verified activation").into(),
                );
            }
            file.sync_all()?;
            pool.sync_all()?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let bytes = serde_json::to_vec(&VerifiedResult {
                schema: RESULT_SCHEMA,
                disposition: VERIFIED_SUCCESS,
                activation,
                evidence,
            })?;
            if bytes.len() as u64 > RESULT_LIMIT {
                return Err(invalid("firmware result exceeds its size bound").into());
            }
            handoff::publish_record(pool, &name, &bytes, &|| Ok(()))?;
        }
        Err(error) => return Err(error.into()),
    }
    if let Err(error) = retire_archive(pool, activation) {
        eprintln!("FVCA_FIRMWARE_CABINET_RETIREMENT_FAILED {error}");
    }
    fs::unlinkat(pool, ACTIVATION, fs::AtFlags::empty())?;
    pool.sync_all()?;
    Ok(())
}

pub(super) fn staged_offer(pool: &File, digest: &str) -> io::Result<File> {
    let staged = handoff::open_child(pool, "staged", DIRECTORY)?;
    handoff::open_child(&staged, digest, DIRECTORY)
}

fn retire_archive(pool: &File, activation: &Activation) -> Result<()> {
    let stage = match staged_offer(pool, &activation.offer_sha256) {
        Ok(directory) => directory,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    match fs::unlinkat(&stage, ARCHIVE, fs::AtFlags::empty()) {
        Ok(()) => stage.sync_all()?,
        Err(Errno::NOENT) => (),
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::save;

    fn record(phase: Phase) -> Activation {
        Activation {
            schema: SCHEMA.into(),
            transaction: "a1234567-d234-4031-a111-000000000000".into(),
            boot_id: "b1234567-d234-4031-a111-000000000000".into(),
            offer_sha256: "1".repeat(64),
            device_id: "2".repeat(40),
            phase,
            guest_was_active: true,
            mains_required: false,
            queued: (phase == Phase::RebootPending).then(|| {
                serde_json::from_value(
                    serde_json::json!({"file": "firmware.cap", "sha256": "3".repeat(64)}),
                )
                .unwrap()
            }),
            esrt_before: None,
        }
    }

    #[test]
    fn preserves_an_interrupted_drain_without_treating_it_as_flashing() -> Result<()> {
        let work = tempfile::tempdir()?;
        let pool = File::open(work.path())?;
        let pending = record(Phase::Draining);
        let path = work.path().join(ACTIVATION);
        save(work.path(), ACTIVATION, &pending)?;
        let before = std::fs::read(&path)?;
        let recovered = Activation::read(File::open(&path)?)?.reconcile(&pool)?;
        assert_eq!(recovered.disposition(), "draining");
        assert_eq!(std::fs::read(&path)?, before);
        Ok(())
    }

    #[test]
    fn writer_start_needs_the_current_boot_and_a_pre_dispatch_phase() {
        for phase in [Phase::Draining, Phase::Flashing] {
            let activation = record(phase);
            assert!(activation.require_writer_boot(&activation.boot_id).is_ok());
            assert!(activation.require_writer_boot("another boot").is_err());
        }
        for phase in [
            Phase::RebootPending,
            Phase::OutcomeUnknown,
            Phase::PowerTransitionPending,
        ] {
            let activation = record(phase);
            assert!(activation.require_writer_boot(&activation.boot_id).is_err());
        }
    }

    #[test]
    fn commits_the_exact_receipt_before_unlocking_and_resumes_an_interrupted_commit() -> Result<()>
    {
        let work = tempfile::tempdir()?;
        let directory = work.path();
        let pool = File::open(directory)?;
        let pending = record(Phase::RebootPending);
        let complete = serde_json::json!({
            "state": "observed",
            "boot_id": "c1234567-d234-4031-a111-000000000000",
            "assessment": "target-reported"
        });
        let path = directory.join(ACTIVATION);
        save(directory, ACTIVATION, &pending)?;
        let stage = directory.join("staged").join(&pending.offer_sha256);
        std::fs::create_dir_all(&stage)?;
        std::fs::write(stage.join(ARCHIVE), b"cabinet")?;
        std::fs::write(stage.join(super::super::OFFER), b"signed offer")?;
        commit_verified(&pool, &pending, &complete)?;
        assert!(!path.try_exists()?);
        assert!(!stage.join(ARCHIVE).try_exists()?);
        assert!(stage.join(super::super::OFFER).is_file());
        let receipt = directory.join(format!("activation-result-{}.json", pending.transaction));
        let retained = std::fs::read(&receipt)?;
        let saved: SavedResult = serde_json::from_slice(&retained)?;
        assert_eq!(saved.disposition, VERIFIED_SUCCESS);
        assert!(saved.activation == pending);
        assert_eq!(saved.evidence, complete);
        if rustix::process::geteuid().is_root() {
            // A crash after synchronizing the receipt can leave the fence.
            save(directory, ACTIVATION, &pending)?;
            let mut next = complete;
            next["boot_id"] = "d1234567-d234-4031-a111-000000000000".into();
            next["assessment"] = "version-only".into();
            assert!(commit_verified(&pool, &pending, &next).is_err());
            assert!(path.try_exists()?);
            next["assessment"] = "target-reported".into();
            commit_verified(&pool, &pending, &next)?;
            assert!(!path.try_exists()?);
            assert_eq!(std::fs::read(receipt)?, retained);
        }
        Ok(())
    }

    #[test]
    fn retains_the_exact_activation_and_never_reconciles_it_to_success() -> Result<()> {
        let work = tempfile::tempdir()?;
        let directory = work.path();
        let path = directory.join(ACTIVATION);
        let pool = File::open(directory)?;
        for (phase, expected) in [
            (Phase::Flashing, Phase::OutcomeUnknown),
            (Phase::RebootPending, Phase::RebootPending),
            (Phase::PowerTransitionPending, Phase::PowerTransitionPending),
            (Phase::OutcomeUnknown, Phase::OutcomeUnknown),
        ] {
            let record = record(phase);
            save(directory, ACTIVATION, &record)?;
            let prior = std::fs::read(&path)?;
            for _ in 0..2 {
                let observed = Activation::read(File::open(&path)?)?.reconcile(&pool)?;
                assert_eq!(observed.phase, expected);
                assert_eq!(observed.transaction, record.transaction);
                assert_eq!(observed.boot_id, record.boot_id);
                assert_eq!(observed.offer_sha256, record.offer_sha256);
                assert_eq!(observed.device_id, record.device_id);
            }
            assert_eq!(Activation::read(File::open(&path)?)?.phase, expected);
            if phase == expected {
                assert_eq!(std::fs::read(&path)?, prior);
            }
        }
        std::fs::write(&path, vec![0; LIMIT as usize + 1])?;
        assert!(Activation::read(File::open(&path)?).is_err());
        Ok(())
    }
}
