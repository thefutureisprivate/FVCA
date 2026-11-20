//! Coordinate a drained Guest, the isolated writer and the hardware reboot.

use std::fs::File;
use std::io;
use std::path::Path;
use std::process::{Command, Stdio};

use fvca_trial_authorization::guest;

use super::{Esrt, Offer, activation::Activation, boot_id, capsule, live, qualification};
use crate::{Result, handoff, invalid};

const GUEST: &str = "fvca-service-guest.service";
const INVENTORY: &str = "fvca-fwupd.service";
const WRITER: &str = "fvca-fwupd-writer.service";

pub(super) fn activate(
    pool: &File,
    lease: &File,
    (offer, offer_sha256, esrt): (&Offer, &str, Esrt),
    prepare: impl FnOnce() -> Result<(live::Session, File, bool)>,
    authorize: &dyn Fn() -> Result<()>,
) -> Result<()> {
    authorize()?;
    let running = guest_active()?;
    let mut operation =
        Activation::begin(pool, offer_sha256, &offer.device.device_id, esrt, running)?;
    let dispatched = (|| {
        if running {
            control(&["stop", GUEST])?;
        }
        verify_drain(&operation, lease)?;
        control(&["stop", INVENTORY])?;
        control(&["start", WRITER])?;
        let (writer, cabinet, mains_required) = prepare()?;
        submit(
            pool,
            &mut operation,
            mains_required,
            authorize,
            |operation| {
                writer.stage_capsule(&cabinet, offer, operation, lease)?;
                capsule::pending_capsule()
            },
        )
    })();
    if let Err(error) = dispatched {
        if operation.is_draining()
            && let Err(cancel) = operation.cancel_drain(pool)
        {
            eprintln!("FVCA_FIRMWARE_DRAIN_RECOVERY_REQUIRED {cancel}");
        }
        return Err(error);
    }
    queue_reboot(&operation)
}

fn submit(
    pool: &File,
    operation: &mut Activation,
    mains_required: bool,
    authorize: &dyn Fn() -> Result<()>,
    stage: impl FnOnce(&Activation) -> Result<capsule::QueuedCapsule>,
) -> Result<()> {
    operation.flash(pool, mains_required, authorize)?;
    match stage(operation) {
        Ok(queued) => operation.mark_queued(pool, queued),
        Err(error) => {
            // The peer can already have written the capsule. Keep its writer,
            // the Guest fence and the selected stage available for recovery.
            if let Err(record) = operation.mark_uncertain(pool) {
                eprintln!("FVCA_FIRMWARE_OUTCOME_RECORD_FAILED {record}");
            }
            Err(error)
        }
    }
}

fn guest_active() -> Result<bool> {
    if !Path::new(guest::SELECTION).try_exists()? {
        return Ok(false);
    }
    let output = systemctl()
        .args(["show", "--property=ActiveState", "--value", GUEST])
        .output()?;
    match (output.status.success(), output.stdout.as_slice()) {
        (true, b"active\n") => Ok(true),
        (true, b"inactive\n") => Ok(false),
        _ => Err(invalid("Service Guest must be in a stable active or inactive state").into()),
    }
}

fn verify_drain(operation: &Activation, lease: &File) -> Result<()> {
    let status = Command::new("/usr/libexec/fvca/launch-guest")
        .env_clear()
        .stdin(Stdio::from(lease.try_clone()?))
        .args([
            "--verify-firmware-drain",
            &operation.transaction,
            &operation.offer_sha256,
        ])
        .status()?;
    if !status.success() {
        return Err(invalid("the Service Guest drain could not be verified").into());
    }
    Ok(())
}

pub(super) fn restore_inventory() -> Result<()> {
    control(&["stop", WRITER])?;
    control(&["start", INVENTORY])
}

pub(super) fn resume_guest() -> Result<()> {
    handoff::request_unit(GUEST, "Service Guest")
}

pub(super) fn queue_reboot(operation: &Activation) -> Result<()> {
    if boot_id()? != operation.boot_id
        || operation.queued.as_ref() != Some(&capsule::pending_capsule()?)
    {
        return Err(invalid("the verified pending firmware capsule queue changed").into());
    }
    if operation.mains_required && !qualification::live_mains()? {
        return Err(invalid("required mains power is unavailable for firmware reboot").into());
    }
    // Starting this target takes the firmware boot path without selecting
    // kexec, a userspace-only reboot or another EFI boot entry.
    control(&[
        "--no-block",
        "--job-mode=replace-irreversibly",
        "start",
        "reboot.target",
    ])
}

fn systemctl() -> Command {
    let mut command = Command::new("/usr/bin/systemctl");
    command
        .env_clear()
        .stdin(Stdio::null())
        .args(["--no-ask-password", "--no-pager"]);
    command
}

fn control(args: &[&str]) -> Result<()> {
    let status = systemctl().args(args).status()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "systemd declined a firmware lifecycle job ({status})"
        ))
        .into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fvca_trial_authorization::firmware::ACTIVATION;

    #[test]
    fn submission_is_fenced_and_ambiguity_cannot_authorize_a_reboot() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let pool = File::open(directory.path())?;
        let path = directory.path().join(ACTIVATION);
        let esrt = Esrt {
            guid: "a1234567-d234-4031-a111-000000000000".into(),
            fw_type: 1,
            fw_version: 65578,
            lowest_supported_fw_version: 65578,
            capsule_flags: 0x50000,
            last_attempt_status: 0,
            last_attempt_version: 65578,
        };
        let mut record =
            Activation::begin(&pool, &"1".repeat(64), &"2".repeat(40), esrt.clone(), true)?;
        let read =
            || -> Result<serde_json::Value> { Ok(serde_json::from_slice(&std::fs::read(&path)?)?) };
        let original = read()?;
        assert_eq!(original["phase"], "draining");
        assert!(
            submit(
                &pool,
                &mut record,
                false,
                &|| Err(invalid("expired").into()),
                |_| { panic!("expiration must prevent dispatch") }
            )
            .is_err()
        );
        assert_eq!(read()?, original);
        assert!(record.is_draining());

        assert!(
            submit(&pool, &mut record, true, &|| Ok(()), |operation| {
                let flashing = read()?;
                assert_eq!(flashing["phase"], "flashing");
                assert_eq!(flashing["transaction"], operation.transaction);
                assert_eq!(flashing["offer_sha256"], operation.offer_sha256);
                assert_eq!(flashing["mains_required"], true);
                Err(invalid("fixture lost the writer reply").into())
            })
            .is_err()
        );
        let uncertain = read()?;
        assert_eq!(uncertain["phase"], "outcome-unknown");
        assert!(uncertain.get("queued").is_none());
        assert!(
            Activation::begin(&pool, &"3".repeat(64), &"2".repeat(40), esrt.clone(), true).is_err()
        );
        assert_eq!(read()?, uncertain);

        let next = tempfile::tempdir()?;
        let next_pool = File::open(next.path())?;
        let mut record =
            Activation::begin(&next_pool, &"3".repeat(64), &"2".repeat(40), esrt, false)?;
        let queued = serde_json::json!({
            "file": "CapsuleUpdateFile0000.bin",
            "sha256": "4".repeat(64),
        });
        submit(&next_pool, &mut record, false, &|| Ok(()), |_| {
            Ok(serde_json::from_value(queued.clone())?)
        })?;
        let pending: serde_json::Value =
            serde_json::from_slice(&std::fs::read(next.path().join(ACTIVATION))?)?;
        assert_eq!(pending["phase"], "reboot-pending");
        assert_eq!(pending["queued"], queued);
        Ok(())
    }
}
