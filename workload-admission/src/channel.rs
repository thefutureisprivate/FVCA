//! Evidence issued by the verified channel client for one local trial.

use serde::{Deserialize, Serialize};

use crate::{Result, VerifiedTransition, current_time, invalid};

pub const READY: &str = "/run/fvca-workload-channel/ready.json";
pub const POLICY: &str = "channel-policy.json";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Permit {
    pub approval: String,
    pub from: String,
    pub to: String,
    pub valid_from: u64,
    pub fresh_until: u64,
}

impl Permit {
    pub fn require_fresh(&self) -> Result<()> {
        if !(self.valid_from..self.fresh_until).contains(&current_time()?) {
            return Err(invalid("the workload channel offer is no longer fresh"));
        }
        Ok(())
    }

    pub fn authorize(&self, transition: &VerifiedTransition) -> Result<()> {
        if self.approval != transition.approval_digest
            || self.from != transition.current.authorization_digest()
            || self.to != transition.candidate.authorization_digest()
        {
            return Err(invalid("the workload channel authorized a different trial"));
        }
        self.require_fresh()
    }
}
