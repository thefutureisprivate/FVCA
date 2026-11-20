//! Durable admission of one desired configuration for the standing Host updater.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use fvca_trial_authorization::{
    MANAGEMENT_INTENTS,
    guest::SERVICE_GUEST_UUID,
    guest_config::{Binding, Change, Configuration, Resources, host_memory_kib},
};
use rustix::fs::{Mode, OFlags, openat};
use rustix::io::Errno;
use serde::Serialize;

use crate::{Result, channel, guest_configuration, handoff, invalid, state, valid_digest};

use super::protocol::{self, Enrollment, Operation, Plan, Refusal, Settings};

const RECORD: &str = "guest-configuration-intent";
const RECORD_SCHEMA: &[u8] = b"FVCA-GUEST-CONFIGURATION-QUEUE-1\n";
const LIMIT: usize = RECORD_SCHEMA.len() + 8 + protocol::REQUEST_BYTES;

struct Intent {
    id: String,
    previous: Option<Binding>,
    next: Binding,
    resources: Resources,
}

impl Intent {
    fn parse(enrollment: &Enrollment, plan: &Plan) -> std::result::Result<Self, Refusal> {
        let previous = plan.expected.clone().map(Binding::from);
        let next = Binding::from(plan.next.clone());
        let resources = Resources {
            vcpus: plan.vcpus,
            memory_mib: plan.memory_mib,
        };
        if previous
            .as_ref()
            .is_some_and(|value| value.revision == 0 || !valid_digest(&value.sha256))
            || previous
                .as_ref()
                .map_or(0, |value| value.revision)
                .checked_add(1)
                != Some(next.revision)
        {
            return Err(Refusal::InvalidConfigurationPlan);
        }
        let selected = Configuration::from_resources(next.revision, resources)
            .map_err(|_| Refusal::OutsideMachineProfile)?;
        let record = selected
            .record()
            .map_err(|_| Refusal::HostStateUnavailable)?;
        if channel::digest(record.as_bytes()) != next.sha256 {
            return Err(Refusal::InvalidConfigurationPlan);
        }
        let prior = previous.as_ref().map_or_else(
            || "default".to_owned(),
            |value| format!("{},{}", value.revision, value.sha256),
        );
        let guest = SERVICE_GUEST_UUID
            .to_str()
            .map_err(|_| Refusal::HostStateUnavailable)?;
        let identity = format!(
            "FVCA-GUEST-CONFIGURATION-INTENT-1\nhost={}\nguest={guest}\nprevious={prior}\nnext={},{}\n",
            enrollment.host, next.revision, next.sha256,
        );
        Ok(Self {
            id: channel::digest(identity.as_bytes()),
            previous,
            next,
            resources,
        })
    }

    fn phase(&self, running: Option<&Binding>, trial: bool) -> Phase {
        if running == Some(&self.next) {
            if trial { Phase::InTrial } else { Phase::Active }
        } else if running == self.previous.as_ref() {
            Phase::PendingActivation
        } else {
            Phase::Superseded
        }
    }

    fn receipt(self, phase: Phase) -> Receipt {
        Receipt {
            operation_id: self.id,
            state: phase,
            configuration: Settings::new(Some(self.next), self.resources),
        }
    }

    fn matches_release(&self, change: &Change) -> bool {
        self.previous == change.previous && self.next == change.next
    }
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Phase {
    PendingActivation,
    InTrial,
    Active,
    Superseded,
}

#[derive(Serialize)]
pub(super) struct Receipt {
    operation_id: String,
    state: Phase,
    configuration: Settings,
}

fn read(directory: &File, enrollment: &Enrollment) -> Result<Option<Intent>> {
    let flags =
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
    let file = match openat(directory, RECORD, flags, Mode::empty()) {
        Ok(fd) => File::from(fd),
        Err(Errno::NOENT) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    handoff::private_file(&file)?;
    let mut data = Vec::new();
    file.take((LIMIT + 1) as u64).read_to_end(&mut data)?;
    if data.len() > LIMIT {
        return Err(invalid("configuration intent record exceeds its size bound").into());
    }
    let (time, packet) = data
        .strip_prefix(RECORD_SCHEMA)
        .and_then(<[u8]>::split_first_chunk::<8>)
        .ok_or_else(|| invalid("invalid stored configuration intent"))?;
    let accepted_at = u64::from_be_bytes(*time);
    if accepted_at > protocol::current_time()? {
        return Err(invalid("configuration intent acceptance is in the future").into());
    }
    let request = protocol::authorize(enrollment, packet, accepted_at)?;
    let Operation::ApplyConfiguration { plan } = request.operation else {
        return Err(invalid("stored request is not a configuration mutation").into());
    };
    if !plan.valid_at(accepted_at) {
        return Err(
            invalid("configuration intent was outside its plan validity at acceptance").into(),
        );
    }
    let intent = Intent::parse(enrollment, &plan)
        .map_err(|_| invalid("stored configuration intent has invalid settings"))?;
    Ok(Some(intent))
}

pub(super) fn status(enrollment: &Enrollment, id: &str) -> std::result::Result<Receipt, Refusal> {
    if !valid_digest(id) {
        return Err(Refusal::UnknownConfigurationOperation);
    }
    let directory = handoff::require_pool_directory(Path::new(MANAGEMENT_INTENTS))
        .map_err(|_| Refusal::HostStateUnavailable)?;
    let selected = read(&directory, enrollment)
        .map_err(|_| Refusal::HostStateUnavailable)?
        .filter(|intent| intent.id == id)
        .ok_or(Refusal::UnknownConfigurationOperation)?;
    let (running, _) = guest_configuration::running().map_err(|_| Refusal::HostStateUnavailable)?;
    let trial = Path::new("/run/fvca/boot-trial-started")
        .try_exists()
        .map_err(|_| Refusal::HostStateUnavailable)?;
    let phase = selected.phase(running.binding.as_ref(), trial);
    Ok(selected.receipt(phase))
}

pub(super) fn submit(
    enrollment: &Enrollment,
    plan: &Plan,
    packet: &[u8],
) -> std::result::Result<Receipt, Refusal> {
    let intent = Intent::parse(enrollment, plan)?;
    let _lease = handoff::lock_install().map_err(|error| {
        if error
            .downcast_ref::<io::Error>()
            .is_some_and(|error| error.kind() == io::ErrorKind::WouldBlock)
        {
            Refusal::LifecycleBusy
        } else {
            Refusal::HostStateUnavailable
        }
    })?;
    let directory = handoff::require_pool_directory(Path::new(MANAGEMENT_INTENTS))
        .map_err(|_| Refusal::HostStateUnavailable)?;
    let (running, current) =
        guest_configuration::running().map_err(|_| Refusal::HostStateUnavailable)?;
    if running.authority.is_none() {
        return Err(Refusal::ConfigurationAuthorityUnavailable);
    }
    let trial = Path::new("/run/fvca/boot-trial-started")
        .try_exists()
        .map_err(|_| Refusal::HostStateUnavailable)?;
    let now = protocol::current_time().map_err(|_| Refusal::HostStateUnavailable)?;
    let previous = read(&directory, enrollment).map_err(|_| Refusal::HostStateUnavailable)?;
    if let Some(previous) = &previous
        && previous.id == intent.id
    {
        let phase = intent.phase(running.binding.as_ref(), trial);
        return Ok(intent.receipt(phase));
    }
    if !plan.valid_at(now) {
        return Err(Refusal::ExpiredConfigurationPlan);
    }
    if trial {
        return Err(Refusal::TrialInProgress);
    }
    handoff::require_idle().map_err(|_| Refusal::LifecycleBusy)?;
    if running.binding != intent.previous {
        return Err(Refusal::StaleConfiguration);
    }
    if previous.is_some_and(|prior| {
        matches!(
            prior.phase(running.binding.as_ref(), trial),
            Phase::PendingActivation | Phase::InTrial
        )
    }) {
        return Err(Refusal::ConfigurationOperationPending);
    }
    if current == intent.resources {
        return Err(Refusal::InvalidConfigurationPlan);
    }
    let meminfo = state::read(Path::new("/proc/meminfo"), 64 * 1024)
        .map_err(|_| Refusal::HostStateUnavailable)?;
    let total = std::str::from_utf8(&meminfo)
        .ok()
        .and_then(|value| host_memory_kib(value, "MemTotal:").ok())
        .ok_or(Refusal::HostStateUnavailable)?;
    let cpus = std::thread::available_parallelism().map_err(|_| Refusal::HostStateUnavailable)?;
    intent
        .resources
        .require_capacity(cpus.get(), total)
        .map_err(|_| Refusal::OutsideHostCapacity)?;
    let mut contents = RECORD_SCHEMA.to_vec();
    contents.extend_from_slice(&now.to_be_bytes());
    contents.extend_from_slice(packet);
    let authorize = || {
        let current = protocol::current_time()?;
        protocol::authorize(enrollment, packet, current)?;
        if current < now || !plan.valid_at(current) {
            return Err(invalid("configuration plan expired during admission").into());
        }
        handoff::require_idle()
    };
    handoff::replace_record(&directory, RECORD, &contents, &authorize)
        .map_err(|_| Refusal::HostStateUnavailable)?;
    println!(
        "FVCA_GUEST_CONFIGURATION_INTENT {} {}",
        intent.id, intent.next.revision
    );
    Ok(intent.receipt(Phase::PendingActivation))
}

pub(super) fn require_release_intent(enrollment: &Enrollment, change: &Change) -> Result<()> {
    let directory = handoff::require_pool_directory(Path::new(MANAGEMENT_INTENTS))?;
    if !read(&directory, enrollment)?.is_some_and(|intent| intent.matches_release(change)) {
        return Err(invalid(
            "qualified release differs from the broker-admitted Guest configuration intent",
        )
        .into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn binds_an_intent_across_retries_and_rejects_other_release_settings() -> Result<()> {
        let enrollment: Enrollment = serde_json::from_value(json!({
            "schema": "fvca-hypervisor-management-v1", "host": "367f5cbc-c46a-437d-af72-5d96d805d234",
            "address": "127.0.0.1:8443", "gateway_uid": 62000, "gateway_gid": 62000,
            "tls_certificate_sha256": "a".repeat(64), "operator_public_key": "b".repeat(64),
            "apply_operator_public_key": "c".repeat(64),
        }))?;
        let digest = "d1bfe17ab1d4bba583943189bf1a98f40381038bf6b768d6d7ab0d4979b62b99";
        let planned = json!({
            "expected": null, "next": {"revision": 1, "sha256": digest}, "vcpus": 3,
            "memory_mib": 2560, "planned_at": 10, "plan_expires": 900,
        });
        let first: Plan = serde_json::from_value(planned.clone())?;
        assert!(first.valid_at(10));
        assert!(!first.valid_at(900));
        let intent = Intent::parse(&enrollment, &first).unwrap();
        let mut retried = planned.clone();
        retried["planned_at"] = json!(900);
        retried["plan_expires"] = json!(1200);
        let retry: Plan = serde_json::from_value(retried)?;
        assert_eq!(intent.id, Intent::parse(&enrollment, &retry).unwrap().id);
        let mut tampered = planned;
        tampered["vcpus"] = json!(4);
        let changed: Plan = serde_json::from_value(tampered)?;
        assert!(matches!(
            Intent::parse(&enrollment, &changed),
            Err(Refusal::InvalidConfigurationPlan)
        ));
        let mut change = Change {
            trial_sha256: "e".repeat(64),
            previous: None,
            next: intent.next.clone(),
        };
        assert!(intent.matches_release(&change));
        change.next.sha256 = "7".repeat(64);
        assert!(!intent.matches_release(&change));
        assert!(matches!(
            intent.phase(None, false),
            Phase::PendingActivation
        ));
        assert!(matches!(
            intent.phase(Some(&intent.next), true),
            Phase::InTrial
        ));
        assert!(matches!(
            intent.phase(Some(&intent.next), false),
            Phase::Active
        ));
        Ok(())
    }
}
