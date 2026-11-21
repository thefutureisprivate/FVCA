//! Admit one exact Guest commissioning offer on the authenticated Host pool.

use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;

use fvca_trial_authorization::{
    commissioning::{self, Offer},
    guest,
    guest_config::{Configuration, host_memory_kib},
};
use rustix::fs::OFlags;
use serde::{Deserialize, Serialize};

use crate::{Result, channel, guest_configuration, handoff, invalid, state};

use super::protocol::{self, Enrollment, Refusal, Settings};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Plan {
    operation_id: String,
    planned_at: u64,
    plan_expires: u64,
}

impl Plan {
    fn valid_at(&self, now: u64) -> bool {
        self.plan_expires.saturating_sub(self.planned_at) <= 900
            && (self.planned_at..self.plan_expires).contains(&now)
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Phase {
    AwaitingApply,
    Pending,
    Ready,
}

#[derive(Serialize)]
pub(super) struct Receipt {
    operation_id: String,
    state: Phase,
    bundle_sha256: String,
    seed_sha256: String,
    disk_bytes: u64,
    configuration: Settings,
}

impl Receipt {
    fn new(enrollment: &Enrollment, body: &str, phase: Phase) -> Result<Self> {
        let offer = Offer::parse(body)?;
        if offer.host != enrollment.host {
            return Err(invalid("the provisioning offer selects another Host").into());
        }
        if let Some(binding) = &offer.configuration {
            let configuration = Configuration::from_resources(binding.revision, offer.resources)?;
            configuration.require_binding(
                binding,
                &channel::digest(configuration.record()?.as_bytes()),
            )?;
        }
        Ok(Self {
            operation_id: channel::digest(body.as_bytes()),
            state: phase,
            bundle_sha256: offer.seed.bundle.to_owned(),
            seed_sha256: offer.seed.digest.to_owned(),
            disk_bytes: offer.seed.bytes,
            configuration: Settings::new(offer.configuration, offer.resources),
        })
    }
}

const RECORD_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::NOCTTY)
    .union(OFlags::CLOEXEC);

fn bounded_record(file: File) -> Result<String> {
    handoff::private_file(&file)?;
    let mut text = String::new();
    file.take((commissioning::LIMIT + 1) as u64)
        .read_to_string(&mut text)?;
    Offer::parse(&text)?;
    Ok(text)
}

fn boot_offer() -> Result<Option<String>> {
    match state::open_regular(Path::new(commissioning::OFFER)) {
        Ok(file) => bounded_record(file).map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn read_record(directory: &str, name: &str) -> Result<Option<String>> {
    let directory = match handoff::require_pool_directory(Path::new(directory)) {
        Ok(directory) => directory,
        Err(error)
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|cause| cause.kind() == io::ErrorKind::NotFound) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    match handoff::open_child(&directory, name, RECORD_FLAGS) {
        Ok(file) => bounded_record(file).map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn observe(enrollment: &Enrollment) -> Result<Option<Receipt>> {
    let current = boot_offer()?;
    let ready = read_record(commissioning::JOURNAL, commissioning::GUEST_READY)?;
    let admitted = read_record(commissioning::QUEUE, commissioning::REQUEST)?;
    match (current, admitted, ready) {
        (_, Some(admitted), Some(ready)) if admitted == ready => {
            Receipt::new(enrollment, &admitted, Phase::Ready).map(Some)
        }
        (_, _, Some(_)) => Err(invalid("Guest readiness differs from the admitted offer").into()),
        (Some(current), Some(admitted), None) if current == admitted => {
            Receipt::new(enrollment, &admitted, Phase::Pending).map(Some)
        }
        (_, Some(_), None) => {
            Err(invalid("the running boot differs from the pending Guest provisioning").into())
        }
        (Some(current), None, None) => {
            Receipt::new(enrollment, &current, Phase::AwaitingApply).map(Some)
        }
        (None, None, None) => Ok(None),
    }
}

pub(super) fn inspect(enrollment: &Enrollment) -> std::result::Result<Receipt, Refusal> {
    observe(enrollment)
        .map_err(|_| Refusal::HostStateUnavailable)?
        .ok_or(Refusal::GuestProvisioningUnavailable)
}

fn require_boot_offer(enrollment: &Enrollment, offer: &Offer<'_>) -> Result<()> {
    let selected = state::read(Path::new(guest::SELECTION), guest::ENVELOPE_LIMIT as u64)?;
    let selected = guest::parse(std::str::from_utf8(&selected)?)?;
    let (configuration, resources) = guest_configuration::running()?;
    if offer.host != enrollment.host
        || offer.seed.bundle != selected.bundle
        || offer.configuration != configuration.binding
        || offer.resources != resources
    {
        return Err(invalid("Guest provisioning differs from the active boot selection").into());
    }
    Ok(())
}

fn require_storage(offer: &Offer<'_>) -> Result<()> {
    let (pool, _) = handoff::host_data()?;
    let journal = handoff::require_pool_directory(Path::new(commissioning::JOURNAL))?;
    let file = handoff::open_child(&journal, "seed.raw", RECORD_FLAGS)?;
    handoff::private_file(&file)?;
    match fs::symlink_metadata("/run/fvca/host-data/vms/service-guest") {
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
        Ok(_) => return Err(invalid("the registered Guest slot already exists").into()),
    }
    if file.metadata()?.len() != offer.seed.bytes
        || !fvca_btrfs_boundary::headroom(&pool)?.affords(offer.seed.bytes, 64 * 1024 * 1024)
    {
        return Err(
            invalid("the vacant Guest slot or authorized seed capacity is unavailable").into(),
        );
    }
    Ok(())
}

pub(super) fn submit(
    enrollment: &Enrollment,
    plan: &Plan,
    packet: &[u8],
) -> std::result::Result<Receipt, Refusal> {
    let current = inspect(enrollment)?;
    if current.operation_id != plan.operation_id {
        return Err(Refusal::StaleGuestProvisioning);
    }
    if current.state != Phase::AwaitingApply {
        return Ok(current);
    }
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
    let current = inspect(enrollment)?;
    if current.operation_id != plan.operation_id {
        return Err(Refusal::StaleGuestProvisioning);
    }
    if current.state != Phase::AwaitingApply {
        return Ok(current);
    }
    let now = protocol::current_time().map_err(|_| Refusal::HostStateUnavailable)?;
    if !plan.valid_at(now) {
        return Err(Refusal::ExpiredGuestProvisioningPlan);
    }
    handoff::require_idle().map_err(|_| Refusal::LifecycleBusy)?;
    let body = boot_offer()
        .map_err(|_| Refusal::HostStateUnavailable)?
        .filter(|text| channel::digest(text.as_bytes()) == plan.operation_id)
        .ok_or(Refusal::StaleGuestProvisioning)?;
    let offer = Offer::parse(&body).map_err(|_| Refusal::HostStateUnavailable)?;
    require_boot_offer(enrollment, &offer).map_err(|_| Refusal::StaleGuestProvisioning)?;
    let meminfo = state::read(Path::new("/proc/meminfo"), 64 * 1024)
        .map_err(|_| Refusal::HostStateUnavailable)?;
    let total = std::str::from_utf8(&meminfo)
        .ok()
        .and_then(|value| host_memory_kib(value, "MemTotal:").ok())
        .ok_or(Refusal::HostStateUnavailable)?;
    let cpus = std::thread::available_parallelism().map_err(|_| Refusal::HostStateUnavailable)?;
    offer
        .resources
        .require_capacity(cpus.get(), total)
        .map_err(|_| Refusal::OutsideHostCapacity)?;
    require_storage(&offer).map_err(|_| Refusal::GuestProvisioningStorageUnavailable)?;
    let queue = handoff::require_pool_directory(Path::new(commissioning::QUEUE))
        .map_err(|_| Refusal::HostStateUnavailable)?;
    let authorize = || {
        let current = protocol::current_time()?;
        protocol::authorize(enrollment, packet, current)?;
        if current < now || !plan.valid_at(current) {
            return Err(invalid("Guest provisioning plan expired during admission").into());
        }
        handoff::require_idle()?;
        require_boot_offer(enrollment, &offer)
    };
    handoff::publish_record(&queue, commissioning::REQUEST, body.as_bytes(), &authorize)
        .map_err(|_| Refusal::HostStateUnavailable)?;
    Receipt::new(enrollment, &body, Phase::Pending).map_err(|_| Refusal::HostStateUnavailable)
}
