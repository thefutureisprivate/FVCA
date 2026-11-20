//! Apply independently authorized firmware promotion after a verified trial.

use std::collections::BTreeSet;
use std::fs::File;
use std::io;
use std::path::Path;
use std::process::Command;

use fvca_trial_authorization::STANDING_PROMOTION;

use super::{
    Authorization, PROMOTION_KEY, Trial, approved_evidence, authorization, boot_next, boot_order,
    digest, gpt_device, promoted_order, publish, read, read_record, standing_promotion,
    verify_signature,
};
use crate::{find_partition, invalid, recovery, run, runtime, sys_block};

struct Approval<'a> {
    esp_after_trial: &'a str,
    stable_core: &'a str,
    stable_runtime: &'a str,
    partitions: [[&'a str; 2]; 3],
    attempt: &'a str,
    health: &'a str,
}

fn pair<'a>(line: &'a str, field: &str) -> io::Result<[&'a str; 2]> {
    let (data, tree) = line
        .strip_prefix(field)
        .and_then(|value| value.split_once(','))
        .ok_or_else(|| invalid("promotion is missing its candidate partition IDs"))?;
    Ok([recovery::uuid(data)?, recovery::uuid(tree)?])
}

fn parse_approval(body: &str) -> io::Result<Approval<'_>> {
    let (header, rest) = body.split_at(
        body.find("FVCA-HYPERVISOR-TRIAL-2\n")
            .ok_or_else(|| invalid("promotion is missing its trial authorization"))?,
    );
    let (attempt, health) = rest.split_at(
        rest.find("FVCA-HYPERVISOR-TRIAL-HEALTH-1\n")
            .ok_or_else(|| invalid("promotion is missing its health receipt"))?,
    );
    let fields: Vec<_> = header.split('\n').collect();
    let [
        "FVCA-HYPERVISOR-PROMOTION-1",
        esp,
        core,
        runtime,
        core_devices,
        runtime_devices,
        guest_devices,
        "",
    ] = fields.as_slice()
    else {
        return Err(invalid("invalid boot promotion approval"));
    };
    Ok(Approval {
        esp_after_trial: digest(esp, "candidate_esp_after_trial=")?,
        stable_core: digest(core, "stable_core=")?,
        stable_runtime: digest(runtime, "stable_runtime=")?,
        partitions: [
            pair(core_devices, "candidate_core_devices=")?,
            pair(runtime_devices, "candidate_runtime_devices=")?,
            pair(guest_devices, "candidate_guest_devices=")?,
        ],
        attempt,
        health,
    })
}

fn verify_installed(
    esp_digest: &str,
    partitions: [[&str; 2]; 3],
    approved: &Authorization<'_>,
) -> io::Result<()> {
    let (device, size) = gpt_device(&approved.trial.candidate)?;
    if size != approved.bytes || recovery::sha256(File::open(&device)?)? != esp_digest {
        return Err(invalid(
            "installed candidate ESP differs from the post-trial promotion approval",
        ));
    }
    verify_payloads(&device, partitions, approved)
}

pub(super) fn verify_payloads(
    device: &Path,
    partitions: [[&str; 2]; 3],
    approved: &Authorization<'_>,
) -> io::Result<()> {
    let esp = sys_block(device)?;
    let disk = esp
        .parent()
        .ok_or_else(|| invalid("candidate ESP has no parent disk"))?;
    let mut used = BTreeSet::from([approved.trial.candidate.esp]);
    for (ids, root) in partitions
        .iter()
        .zip([approved.core, approved.runtime, approved.guest])
    {
        let mut verify = Command::new("/usr/bin/veritysetup");
        verify.arg("verify");
        for &id in ids {
            let partition = find_partition(id)?
                .ok_or_else(|| invalid("candidate promotion partition is missing"))?;
            if !used.insert(id) || sys_block(&partition)?.parent() != Some(disk) {
                return Err(invalid(
                    "candidate promotion partitions must be distinct and share the candidate disk",
                ));
            }
            verify.arg(partition);
        }
        run(verify.arg(root))?;
    }
    Ok(())
}

pub(super) fn pinned_key() -> io::Result<Option<[u8; 32]>> {
    match read(Path::new(PROMOTION_KEY), 32) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        result => Ok(Some(
            result?
                .try_into()
                .map_err(|_| invalid("invalid pinned promotion key"))?,
        )),
    }
}

pub(super) fn record_candidate_key(directory: &Path, tx: &str) -> io::Result<()> {
    if let Some(key) = pinned_key()? {
        let path = directory.join(format!("{tx}.promotion-key"));
        match publish(&path, &key) {
            Err(error)
                if error.kind() == io::ErrorKind::AlreadyExists && read_record(&path)? == key => {}
            result => result?,
        }
    }
    Ok(())
}

pub(super) fn apply(
    directory: &Path,
    approved: &Authorization<'_>,
    attempt: &[u8],
    health: &[u8],
    active: &runtime::Activation,
    order: &[u16],
) -> io::Result<()> {
    let Some(key) = pinned_key()? else {
        return Ok(());
    };
    let trial = &approved.trial;
    let tx = trial.transaction;
    let pending = directory.join(format!("{tx}.promotion"));
    let envelope = match read_record(&pending) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        result => result?,
    };
    let approval = parse_approval(verify_signature("promotion", &envelope)?)?;
    if read_record(&directory.join(format!("{tx}.promotion-key")))? != key {
        return Err(invalid(
            "the trial candidate pinned a different promotion authority",
        ));
    }
    if approval.attempt.as_bytes() != attempt
        || approval.health.as_bytes() != health
        || approval.stable_core != active.core
        || approval.stable_runtime != active.extension
    {
        return Err(invalid(
            "promotion approval differs from the trial, health receipt or running recovery slot",
        ));
    }
    let wanted = promoted_order(order, trial.stable.id, trial.candidate.id)?;
    if boot_next()?.is_some() {
        return Err(invalid("promotion cannot override a pending one-shot boot"));
    }
    verify_installed(approval.esp_after_trial, approval.partitions, approved)?;

    // Commit authorization before the only firmware write. An interrupted write
    // leaves either a usable default candidate or the original recovery order.
    let intent = directory.join(format!("{tx}.promotion-intent"));
    publish(&intent, &envelope).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            invalid("this boot promotion was already attempted")
        } else {
            error
        }
    })?;
    run(Command::new("/usr/lib/fvca/set-boot-order")
        .arg(trial.stable.id.to_string())
        .arg(trial.candidate.id.to_string()))?;
    if boot_order()? != wanted {
        return Err(invalid(
            "firmware BootOrder differs from the approved promotion",
        ));
    }
    println!("FVCA_BOOT_PROMOTED {tx}");
    Ok(())
}

pub(super) fn authorize_promoted(
    directory: &Path,
    trial: &Trial<'_>,
    guest: Option<&str>,
    active: &runtime::Activation,
    order: &[u16],
    (payload_ids, cmdline): (&[String; 6], &str),
) -> io::Result<()> {
    let default = order.get(..2) == Some(&[trial.candidate.id, trial.stable.id]);
    if !default && order.get(..2) != Some(&[trial.stable.id, trial.candidate.id]) {
        return Err(invalid(
            "promoted boot must retain the authorized stable recovery entry",
        ));
    }
    let tx = trial.transaction;
    let envelope =
        read_record(&directory.join(format!("{tx}.promotion-intent"))).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                invalid("default candidate lacks a durable promotion approval")
            } else {
                error
            }
        })?;
    let body = verify_signature("promotion", &envelope)?;
    if body.starts_with(STANDING_PROMOTION) {
        return standing_promotion::authorize_boot(
            directory,
            trial,
            guest,
            active,
            payload_ids,
            (body, default, cmdline),
        );
    }
    if !default {
        return Err(invalid(
            "candidate-first order is required by this promotion",
        ));
    }
    let approval = parse_approval(body)?;
    let approved = authorization(approval.attempt)?;
    approved_evidence(&approved, approval.health.as_bytes())?;
    if *trial != approved.trial
        || guest != Some(approved.guest)
        || active.core != approved.core
        || active.extension != approved.runtime
        || !approval
            .partitions
            .iter()
            .flatten()
            .copied()
            .eq(payload_ids.iter().map(String::as_str))
    {
        return Err(invalid(
            "default candidate differs from its signed promotion composition",
        ));
    }
    gpt_device(&trial.candidate)?;
    println!("FVCA_PROMOTED_HYPERVISOR_ACTIVE {tx}");
    Ok(())
}
