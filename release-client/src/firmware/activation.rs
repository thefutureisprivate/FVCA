//! Reconcile interrupted activation before renewing or retiring firmware staging.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use fvca_trial_authorization::firmware::{ACTIVATION, activation_pending};
use rustix::fs::{self, Mode, OFlags, ResolveFlags};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};

use super::{Esrt, lower_hex, result, uuid};
use crate::{Result, channel::save, handoff, invalid, valid_digest};

const SCHEMA: &str = "fvca-firmware-activation-v1";
const LIMIT: u64 = 1024;

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Phase {
    Flashing,
    RebootPending,
    PowerTransitionPending,
    OutcomeUnknown,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Activation {
    schema: String,
    transaction: String,
    pub(super) boot_id: String,
    pub(super) offer_sha256: String,
    pub(super) device_id: String,
    phase: Phase,
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
        {
            return Err(invalid("invalid firmware activation identity").into());
        }
        Ok(record)
    }

    fn reconcile(mut self, directory: &Path) -> Result<Self> {
        if self.phase == Phase::Flashing {
            // An updater which still owns the lifecycle lease cannot reach this
            // observation. The device may nevertheless be completing a write.
            self.phase = Phase::OutcomeUnknown;
            save(directory, ACTIVATION, &self)?;
        }
        Ok(self)
    }

    pub(super) fn disposition(&self) -> &'static str {
        match self.phase {
            Phase::Flashing => "flashing",
            Phase::RebootPending => "reboot-pending",
            Phase::PowerTransitionPending => "power-transition-pending",
            Phase::OutcomeUnknown => "outcome-unknown",
        }
    }
}

pub(super) fn recover(
    directory: &Path,
    pool_directory: &File,
) -> Result<Option<(Activation, result::Evidence)>> {
    if !activation_pending()? {
        return Ok(None);
    }
    let _lease = handoff::lock_install()?;
    let file = match fs::openat2(
        pool_directory,
        ACTIVATION,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
    ) {
        Ok(fd) => File::from(fd),
        Err(Errno::NOENT) => {
            return Err(
                invalid("firmware activation disappeared while acquiring its lease").into(),
            );
        }
        Err(error) => return Err(error.into()),
    };
    handoff::private_file(&file)?;
    let activation = Activation::read(file)?.reconcile(directory)?;
    let evidence = result::inspect(pool_directory, &activation);
    Ok(Some((activation, evidence)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retains_the_exact_activation_and_never_reconciles_it_to_success() -> Result<()> {
        let work = tempfile::tempdir()?;
        let directory = work.path();
        let path = directory.join(ACTIVATION);
        for (phase, expected) in [
            (Phase::Flashing, Phase::OutcomeUnknown),
            (Phase::RebootPending, Phase::RebootPending),
            (Phase::PowerTransitionPending, Phase::PowerTransitionPending),
            (Phase::OutcomeUnknown, Phase::OutcomeUnknown),
        ] {
            let record = Activation {
                schema: SCHEMA.into(),
                transaction: "a1234567-d234-4031-a111-000000000000".into(),
                boot_id: "b1234567-d234-4031-a111-000000000000".into(),
                offer_sha256: "1".repeat(64),
                device_id: "2".repeat(40),
                phase,
                esrt_before: None,
            };
            save(directory, ACTIVATION, &record)?;
            let prior = std::fs::read(&path)?;
            for _ in 0..2 {
                let observed = Activation::read(File::open(&path)?)?.reconcile(directory)?;
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
