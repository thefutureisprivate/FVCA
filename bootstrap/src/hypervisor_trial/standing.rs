//! Verify an off-node trial authorization against the booted release.

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use fvca_trial_authorization::Standing;

use super::verify_signature;
use crate::{HYPERVISOR_EPOCH_ARGUMENT, invalid, runtime};

pub(super) fn verify(envelope: &[u8]) -> io::Result<Standing<'_>> {
    Standing::parse(verify_signature("trial", envelope)?)
}

pub(super) fn require_epoch(
    approval: &Standing<'_>,
    marker: Option<&str>,
    expected: u64,
) -> io::Result<()> {
    let value = format!(
        "{HYPERVISOR_EPOCH_ARGUMENT}={expected},{}",
        approval.epoch_policy
    );
    if marker != Some(value.as_str()) {
        return Err(invalid(
            "standing trial does not authorize this release epoch and enrollment",
        ));
    }
    Ok(())
}

pub(super) fn require_stable(
    approval: &Standing<'_>,
    active: &runtime::Activation,
    guest: Option<&str>,
    epoch: Option<&str>,
) -> io::Result<()> {
    if [
        Some(active.core.as_str()),
        Some(active.extension.as_str()),
        guest,
    ] != approval.stable_roots.map(Some)
    {
        return Err(invalid(
            "standing trial differs from the running stable composition",
        ));
    }
    require_epoch(approval, epoch, approval.stable_epoch)
}

pub(super) fn require_fresh(approval: &Standing<'_>) -> io::Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs();
    approval.require_fresh(now)
}
