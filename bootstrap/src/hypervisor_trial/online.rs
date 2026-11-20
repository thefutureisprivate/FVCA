//! Check that the pending approval can be handed off by the running stable release.

use std::io;
use std::path::{Path, PathBuf};

use fvca_trial_authorization::Standing;

use super::{
    PENDING, RUNNING_CONTEXT, boot_next, boot_order, gpt_device, read_record, selected, standing,
    verify_candidate_esp,
};
use crate::invalid;

pub struct PendingTrial {
    directory: PathBuf,
    bytes: Vec<u8>,
}

impl PendingTrial {
    pub fn verify() -> io::Result<Self> {
        let context = read_record(Path::new(RUNNING_CONTEXT))?;
        let (key, _) = context
            .split_first_chunk::<32>()
            .ok_or_else(|| invalid("missing verified running trial context"))?;
        let directory = super::record_directory()?;
        let bytes = read_record(&directory.join(PENDING))?;
        let (signature, payload) = bytes
            .split_first_chunk::<64>()
            .ok_or_else(|| invalid("truncated signed trial approval"))?;
        fvca_signature_boundary::verify_ed25519(key, signature, payload)?;
        let approval = Standing::parse(std::str::from_utf8(payload).map_err(io::Error::other)?)?;
        approval.require_running_context(key, &context)?;
        let trial = &approval.authorization.trial;
        check_pending(&directory, &approval)?;
        gpt_device(&trial.stable)?;
        verify_candidate_esp(&approval.authorization)?;
        Ok(Self { directory, bytes })
    }

    pub fn recheck(&self) -> io::Result<()> {
        if read_record(&self.directory.join(PENDING))? != self.bytes {
            return Err(invalid("pending trial changed during Guest shutdown"));
        }
        check_pending(&self.directory, &self.approval())
    }

    pub fn transaction(&self) -> &str {
        self.approval().authorization.trial.transaction
    }

    fn approval(&self) -> Standing<'_> {
        let payload = std::str::from_utf8(&self.bytes[64..]).expect("verified trial payload UTF-8");
        Standing::parse(payload).expect("verified trial approval")
    }
}

fn check_pending(directory: &Path, approval: &Standing<'_>) -> io::Result<()> {
    standing::require_fresh(approval)?;
    let trial = &approval.authorization.trial;
    match directory.join(trial.transaction).symlink_metadata() {
        Ok(_) => {
            return Err(invalid(
                "the signed trial transaction has already been consumed",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error),
    }
    if selected()? != trial.stable.id
        || boot_order()?.get(..2) != Some(&[trial.stable.id, trial.candidate.id])
        || boot_next()?.is_some()
    {
        return Err(invalid(
            "firmware does not select the approved stable slot without an override",
        ));
    }
    Ok(())
}
