//! Verify an off-node trial authorization bound to both protected releases.

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{digest, verify_signature};
use crate::{invalid, runtime};

pub(super) const PENDING: &str = "pending-trial";
const EPOCH_ARGUMENT: &str = "fvca.hypervisor_epoch";

pub(super) struct Standing<'a> {
    pub attempt: &'a str,
    stable: [&'a str; 3],
    stable_epoch: u64,
    candidate_epoch: u64,
    epoch_policy: &'a str,
    not_before: u64,
    expires: u64,
}

fn number(field: &str, prefix: &str) -> io::Result<u64> {
    field
        .strip_prefix(prefix)
        .filter(|value| !value.starts_with('0') && value.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| invalid("invalid standing trial number"))
}

fn parse(body: &str) -> io::Result<Standing<'_>> {
    let (header, attempt) = body.split_at(
        body.find("FVCA-HYPERVISOR-TRIAL-2\n")
            .ok_or_else(|| invalid("standing trial lacks its candidate authorization"))?,
    );
    let fields: Vec<_> = header.split('\n').collect();
    let [
        "FVCA-HYPERVISOR-STANDING-TRIAL-1",
        from,
        until,
        stable_epoch,
        candidate_epoch,
        epoch_policy,
        core,
        vm_runtime,
        guest,
        "",
    ] = fields.as_slice()
    else {
        return Err(invalid("invalid standing trial approval"));
    };
    let not_before = number(from, "not_before=")?;
    let expires = number(until, "expires=")?;
    let stable_epoch = number(stable_epoch, "stable_epoch=")?;
    let candidate_epoch = number(candidate_epoch, "candidate_epoch=")?;
    if !expires
        .checked_sub(not_before)
        .is_some_and(|length| (1..=86_400).contains(&length))
        || candidate_epoch < stable_epoch
    {
        return Err(invalid(
            "standing trial exceeds its validity or epoch bounds",
        ));
    }
    Ok(Standing {
        attempt,
        stable: [
            digest(core, "stable_core=")?,
            digest(vm_runtime, "stable_runtime=")?,
            digest(guest, "stable_guest_bundle=")?,
        ],
        stable_epoch,
        candidate_epoch,
        epoch_policy: digest(epoch_policy, "epoch_policy_sha256=")?,
        not_before,
        expires,
    })
}

pub(super) fn verify(envelope: &[u8]) -> io::Result<Standing<'_>> {
    parse(verify_signature("trial", envelope)?)
}

impl Standing<'_> {
    fn require_epoch(&self, marker: Option<&str>, expected: u64) -> io::Result<()> {
        let value = format!("{EPOCH_ARGUMENT}={expected},{}", self.epoch_policy);
        if marker != Some(value.as_str()) {
            return Err(invalid(
                "standing trial does not authorize this release epoch and enrollment",
            ));
        }
        Ok(())
    }

    pub fn require_stable(
        &self,
        active: &runtime::Activation,
        guest: Option<&str>,
        epoch: Option<&str>,
    ) -> io::Result<()> {
        if [
            Some(active.core.as_str()),
            Some(active.extension.as_str()),
            guest,
        ] != self.stable.map(Some)
        {
            return Err(invalid(
                "standing trial differs from the running stable composition",
            ));
        }
        self.require_epoch(epoch, self.stable_epoch)
    }

    pub fn require_candidate(&self, epoch: Option<&str>) -> io::Result<()> {
        self.require_epoch(epoch, self.candidate_epoch)
    }

    pub fn require_fresh(&self) -> io::Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_secs();
        if !(self.not_before..self.expires).contains(&now) {
            return Err(invalid(
                "standing trial is outside its signed validity interval",
            ));
        }
        Ok(())
    }
}
