//! Arm and observe one authorized Hypervisor candidate boot.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub use fvca_trial_authorization::APPROVAL_LIMIT;
use fvca_trial_authorization::{
    Authorization, Entry, GUEST_CAPTURE_LOCK, PENDING, RUNNING_CONTEXT, Trial, authorization, efi,
    trial,
};

use crate::{find_partition, identity, invalid, recovery, runtime, sys_block};

mod attempts;
mod promotion;
mod standing;
mod standing_promotion;
mod watchdog;

pub const PROMOTION_KEY: &str = "/usr/lib/fvca/hypervisor-promotion-key";
pub const TRIAL_KEY: &str = "/usr/lib/fvca/hypervisor-trial-key";
const AUTHORIZATION: &str = "/usr/lib/fvca/hypervisor-trial";
const CANDIDATE: &str = "/usr/lib/fvca/hypervisor-trial-candidate";
const CANDIDATE_ARGUMENT: &str = "fvca.hypervisor_trial";
const BOOT_ID: &str = "/proc/sys/kernel/random/boot_id";
const STARTED: &str = "/run/fvca/boot-trial-started";
const REBOOT_PENDING: &str = "/run/fvca/trial-reboot-pending";
const HOST_DATA: &str = "/run/fvca/host-data";
const EFI: &str = "/sys/firmware/efi/efivars";
const ATTRIBUTES: u32 = 7;
const O_NONBLOCK: i32 = 0o4000;
const O_NOFOLLOW: i32 = 0o400000;
const HEALTH_UNIT: &str = concat!(
    "[Unit]\nDescription=Record the verified FVCA candidate boot health\n",
    "Requires=fvca-base-ready.service\nAfter=fvca-base-ready.service\n",
    "Before=fvca-base.target\nOnFailure=emergency.target\n",
    "[Service]\nType=oneshot\nRemainAfterExit=yes\nTimeoutStartSec=20s\n",
    "SELinuxContext=system_u:system_r:init_t:s0\n",
    "ExecStart=/usr/libexec/fvca/trial-health\n",
    "NoNewPrivileges=yes\nMemoryDenyWriteExecute=yes\n",
    "StandardOutput=journal+console\nStandardError=journal+console\n",
);

struct Evidence<'a> {
    transaction: &'a str,
    boot: &'a str,
    candidate: &'a str,
    esp_digest: &'a str,
    core: &'a str,
    guest: &'a str,
    runtime: &'a str,
}

pub enum ArmOutcome {
    ContinueBoot,
    RebootIntoTrial,
}

pub fn reboot_into_trial() -> io::Result<()> {
    // The switch-root unit checks this marker while systemd processes the shutdown transaction.
    publish(Path::new(REBOOT_PENDING), b"")?;
    println!("FVCA_TRIAL_REBOOT_REQUESTED");
    queue_host_reboot()
}

pub fn queue_host_reboot() -> io::Result<()> {
    fvca_trial_authorization::firmware::require_idle()?;
    crate::run(Command::new("/usr/bin/systemctl").args([
        "--no-block",
        "--job-mode=replace-irreversibly",
        "start",
        "reboot.target",
    ]))
}

pub fn publish_running_context(
    esp: &str,
    active: &runtime::Activation,
    guest: &str,
    epoch: &str,
) -> io::Result<()> {
    let mut key = match read(Path::new(TRIAL_KEY), 32) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        result => result?,
    };
    if key.len() != 32 {
        return Err(invalid("invalid verified trial authority"));
    }
    key.extend_from_slice(
        format!(
            "{esp}\n{}\n{}\n{guest}\n{epoch}\n",
            active.core, active.extension
        )
        .as_bytes(),
    );
    // This private /run record carries the verified UKI composition across switch-root.
    publish(Path::new(RUNNING_CONTEXT), &key)
}

#[cfg(feature = "promotion")]
pub mod online;
#[cfg(feature = "promotion")]
pub use standing_promotion::healthy_return;

pub fn verify_standing_key(cmdline: &str) -> io::Result<()> {
    use fvca_trial_authorization::{KEY_ARGUMENT, key_marker};
    let mut markers = cmdline
        .split_ascii_whitespace()
        .filter(|arg| arg.split('=').next() == Some(KEY_ARGUMENT));
    let marker = markers.next();
    let key = match read(Path::new(TRIAL_KEY), 32) {
        Err(error) if error.kind() == io::ErrorKind::NotFound && marker.is_none() => return Ok(()),
        result => result?,
    };
    if key.len() != 32 || marker != Some(key_marker(&key).as_str()) || markers.next().is_some() {
        return Err(invalid(
            "UKI trial key marker differs from the signed initramfs authority",
        ));
    }
    Ok(())
}

fn digest<'a>(line: &'a str, field: &str) -> io::Result<&'a str> {
    runtime::hash(
        line.strip_prefix(field)
            .ok_or_else(|| invalid("missing trial digest"))?,
    )
}

fn candidate_selection(text: &str) -> io::Result<Trial<'_>> {
    let fields: Vec<_> = text.split('\n').collect();
    let [
        "FVCA-HYPERVISOR-TRIAL-CANDIDATE-1",
        transaction,
        stable,
        candidate,
        "",
    ] = fields.as_slice()
    else {
        return Err(invalid("invalid candidate trial selection"));
    };
    trial(transaction, stable, candidate)
}

fn variable(name: &str) -> PathBuf {
    Path::new(EFI).join(format!("{name}-{}", efi::GLOBAL))
}

pub fn boot_next_path() -> PathBuf {
    variable("BootNext")
}

fn read(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    bounded_read(File::open(path)?, limit)
}

fn bounded_read(file: File, limit: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(invalid("trial record exceeds its size bound"));
    }
    Ok(bytes)
}

fn efi_data(name: &str, attributes: u32) -> io::Result<Vec<u8>> {
    let bytes = read(&variable(name), 4096)?;
    Ok(efi::variable_data(&bytes, attributes)?.to_owned())
}

fn selected() -> io::Result<u16> {
    let value = efi_data("BootCurrent", 6)?;
    Ok(u16::from_le_bytes(
        value
            .try_into()
            .map_err(|_| invalid("malformed EFI BootCurrent"))?,
    ))
}

fn boot_order() -> io::Result<Vec<u16>> {
    efi::boot_order(&efi_data("BootOrder", ATTRIBUTES)?)
}

fn promoted_order(current: &[u16], stable: u16, candidate: u16) -> io::Result<Vec<u16>> {
    if stable == candidate || current.get(..2) != Some(&[stable, candidate]) {
        return Err(invalid(
            "EFI BootOrder must start with the approved stable and candidate entries",
        ));
    }
    let mut order = current.to_vec();
    order.swap(0, 1);
    Ok(order)
}

pub fn write_promoted_order(stable: u16, candidate: u16) -> io::Result<()> {
    if selected()? != stable || boot_next()?.is_some() {
        return Err(invalid(
            "boot promotion requires the selected stable slot with no one-shot override",
        ));
    }
    let order = promoted_order(&boot_order()?, stable, candidate)?;
    let mut payload = ATTRIBUTES.to_le_bytes().to_vec();
    payload.extend(order.iter().flat_map(|id| id.to_le_bytes()));
    // efivarfs passes a complete payload to one EFI SetVariable call.
    let mut variable = OpenOptions::new().write(true).open(variable("BootOrder"))?;
    if variable.write(&payload)? != payload.len() || boot_order()? != order {
        return Err(invalid("firmware did not store the approved boot order"));
    }
    Ok(())
}

fn boot_next() -> io::Result<Option<u16>> {
    match efi_data("BootNext", ATTRIBUTES) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
        Ok(value) => Ok(Some(u16::from_le_bytes(
            value
                .try_into()
                .map_err(|_| invalid("malformed EFI BootNext"))?,
        ))),
    }
}

fn number(path: &Path) -> io::Result<u64> {
    fs::read_to_string(path)?
        .trim_end()
        .parse()
        .map_err(io::Error::other)
}

fn esp_device(esp: &str) -> io::Result<(PathBuf, u64, Vec<u8>)> {
    let device = find_partition(esp)?.ok_or_else(|| invalid("authorized Host ESP is missing"))?;
    let partition = sys_block(&device)?;
    let disk = partition
        .parent()
        .ok_or_else(|| invalid("trial ESP does not have a parent disk"))?;
    let sector = number(&disk.join("queue/logical_block_size"))?;
    if !matches!(sector, 512 | 4096) {
        return Err(invalid("unsupported trial ESP logical sector size"));
    }
    let sectors_per_block = sector / 512;
    let start = number(&partition.join("start"))?;
    let size = number(&partition.join("size"))?;
    if !start.is_multiple_of(sectors_per_block)
        || size == 0
        || !size.is_multiple_of(sectors_per_block)
    {
        return Err(invalid("invalid trial ESP geometry"));
    }
    let partition_index =
        u32::try_from(number(&partition.join("partition"))?).map_err(io::Error::other)?;

    Ok((
        device,
        size.checked_mul(512)
            .ok_or_else(|| invalid("trial ESP size overflow"))?,
        efi::esp_device_path(
            esp,
            partition_index,
            start / sectors_per_block,
            size / sectors_per_block,
        )?,
    ))
}

fn gpt_device(entry: &Entry<'_>) -> io::Result<(PathBuf, u64)> {
    let (device, bytes, expected) = esp_device(entry.esp)?;
    let raw = efi_data(&format!("Boot{:04X}", entry.id), ATTRIBUTES)?;
    efi::require_esp_load_option(&raw, &expected)?;
    Ok((device, bytes))
}

pub(crate) fn publish_firmware_esp(esp: &str) -> io::Result<()> {
    match publish(Path::new(GUEST_CAPTURE_LOCK), b"") {
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (),
        result => result?,
    }
    let (device, _, path) = esp_device(esp)?;
    let device_id = fs::metadata(&device)?.rdev();
    let mountpoint = Path::new(efi::FIRMWARE_ESP);
    DirBuilder::new().mode(0o700).create(mountpoint)?;
    crate::run(
        Command::new("/usr/bin/mount")
            .args([
                "--internal-only",
                "--types",
                "vfat",
                "--options",
                "ro,nodev,nosuid,noexec,umask=0077,codepage=437,iocharset=iso8859-1,utf8",
            ])
            .arg(device)
            .arg(mountpoint),
    )?;
    if fs::metadata(mountpoint)?.dev() != device_id {
        return Err(invalid(
            "mounted firmware ESP differs from the verified partition",
        ));
    }
    let mut binding = device_id.to_le_bytes().to_vec();
    binding.extend_from_slice(&path);
    publish(Path::new(efi::FIRMWARE_ESP_BINDING), &binding)
}

pub(crate) fn publish_firmware_boot(
    esp: &str,
    epoch: &str,
    active: &runtime::Activation,
    filesystem: &str,
    storage_policy_sha256: &str,
    tpm: &crate::host_update::FirmwareTpm,
) -> io::Result<()> {
    use fvca_trial_authorization::firmware::{VERIFIED_BOOT, VerifiedBoot};

    let epoch = epoch
        .strip_prefix(crate::HYPERVISOR_EPOCH_ARGUMENT)
        .and_then(|value| value.strip_prefix('='))
        .ok_or_else(|| invalid("missing accepted firmware boot epoch"))?;
    let boot = boot_id()?;
    let contents = format!(
        "FVCA-FIRMWARE-BOOT-2\nboot_id={boot}\nesp={esp}\ncore={}\nruntime={}\nepoch={epoch}\ntpm_floor={}\npcr7_sha256={}\nfilesystem={filesystem}\nstorage_policy_sha256={storage_policy_sha256}\n",
        active.core, active.extension, tpm.floor, tpm.pcr7_sha256,
    );
    VerifiedBoot::parse(&contents)?;
    publish(Path::new(VERIFIED_BOOT), contents.as_bytes())
}

fn record_directory() -> io::Result<PathBuf> {
    let root = Path::new(HOST_DATA);
    let path = root.join("boot-trials");
    match DirBuilder::new().mode(0o700).create(&path) {
        Ok(()) => File::open(root)?.sync_all()?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error),
    }
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(invalid(
            "boot trial state requires a private Host directory",
        ));
    }
    Ok(path)
}

fn read_record(path: &Path) -> io::Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(invalid("boot trial record is not a private Host file"));
    }
    bounded_read(file, APPROVAL_LIMIT)
}

fn verify_signature<'a>(purpose: &str, envelope: &'a [u8]) -> io::Result<&'a str> {
    let mut verifier = Command::new("/usr/lib/fvca/verify-boot-approval")
        .arg(purpose)
        .env_clear()
        .stdin(Stdio::piped())
        .spawn()?;
    let written = verifier
        .stdin
        .take()
        .expect("verifier input is piped")
        .write_all(envelope);
    let status = verifier.wait()?;
    written?;
    if !status.success() {
        return Err(invalid(&format!(
            "boot {purpose} requires an independently signed approval"
        )));
    }
    let (_, body) = envelope
        .split_first_chunk::<64>()
        .ok_or_else(|| invalid("truncated boot approval"))?;
    std::str::from_utf8(body).map_err(io::Error::other)
}

fn publish(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    File::open(
        path.parent()
            .ok_or_else(|| invalid("missing trial record directory"))?,
    )?
    .sync_all()
}

fn verify_candidate_esp(approved: &Authorization<'_>) -> io::Result<()> {
    let (candidate, size) = gpt_device(&approved.trial.candidate)?;
    if size != approved.bytes || recovery::sha256(File::open(candidate)?)? != approved.digest {
        return Err(invalid("candidate ESP differs from the approved image"));
    }
    Ok(())
}

fn approved_evidence<'a>(
    approved: &Authorization<'_>,
    receipt: &'a [u8],
) -> io::Result<Evidence<'a>> {
    let evidence = evidence(receipt)?;
    if evidence.transaction != approved.trial.transaction
        || evidence.candidate != approved.trial.candidate.esp
        || evidence.esp_digest != approved.digest
        || evidence.core != approved.core
        || evidence.runtime != approved.runtime
        || evidence.guest != approved.guest
    {
        return Err(invalid(
            "candidate health does not match the authorized trial",
        ));
    }
    Ok(evidence)
}

fn prior_health(
    directory: &Path,
    approved: &Authorization<'_>,
    attempt: attempts::Attempt,
) -> io::Result<Option<Vec<u8>>> {
    let id = approved.trial.transaction;
    let receipt = match read_record(&directory.join(format!("{id}.healthy"))) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        prior => prior?,
    };
    attempt.require_armed(directory, id)?;
    let evidence = approved_evidence(approved, &receipt)?;
    if read_record(&attempt.path(directory, id, ".started"))? != receipt {
        return Err(invalid(
            "recorded candidate health does not match the authorized attempt",
        ));
    }
    println!(
        "FVCA_TRIAL_HEALTH_AVAILABLE {id} {} {}",
        evidence.boot, evidence.runtime
    );
    Ok(Some(receipt))
}

pub fn arm_if_authorized(
    current_esp: Option<&str>,
    guest: Option<&str>,
    active: &runtime::Activation,
    epoch: Option<&str>,
) -> io::Result<ArmOutcome> {
    let dynamic = Path::new(TRIAL_KEY).try_exists()?;
    let directory;
    let raw = if dynamic {
        if Path::new(AUTHORIZATION).try_exists()? {
            return Err(invalid(
                "standing trial authority conflicts with an embedded trial",
            ));
        }
        if current_esp.is_none() || guest.is_none() {
            return Err(invalid(
                "standing trials require the verified Host GPT and Guest bundle",
            ));
        }
        directory = record_directory()?;
        match read_record(&directory.join(PENDING)) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(ArmOutcome::ContinueBoot);
            }
            result => result?,
        }
    } else {
        match read(Path::new(AUTHORIZATION), 1024) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(ArmOutcome::ContinueBoot);
            }
            result => result?,
        }
    };
    let standing = dynamic.then(|| standing::verify(&raw)).transpose()?;
    let text = match &standing {
        Some(standing) => standing.attempt,
        None => std::str::from_utf8(&raw).map_err(io::Error::other)?,
    };
    let approved = authorization(text)?;
    let trial = &approved.trial;
    if let Some(standing) = &standing {
        if current_esp == Some(trial.candidate.esp) {
            return Ok(ArmOutcome::ContinueBoot);
        }
        standing::require_stable(standing, active, guest, epoch)?;
    } else if guest != Some(approved.guest) {
        return Err(invalid(
            "stable boot must use the approved trial Guest bundle",
        ));
    }
    if current_esp != Some(trial.stable.esp) || selected()? != trial.stable.id {
        return Err(invalid(
            "the firmware must have selected the signed stable slot",
        ));
    }
    gpt_device(&trial.stable)?;
    let order = boot_order()?;
    if order.get(..2) == Some(&[trial.candidate.id, trial.stable.id]) {
        println!("FVCA_PROMOTION_STABLE_RECOVERY {}", trial.transaction);
        return Ok(ArmOutcome::ContinueBoot);
    }
    if order.first() != Some(&trial.stable.id)
        || (dynamic && order.get(1) != Some(&trial.candidate.id))
    {
        return Err(invalid(
            "the signed stable slot must be booted and first in EFI BootOrder",
        ));
    }
    let directory = record_directory()?;
    let tx = trial.transaction;
    let record = directory.join(tx);
    let previously_recorded = match read_record(&record) {
        Ok(prior) if prior == raw => {
            println!("FVCA_TRIAL_PREVIOUSLY_RECORDED {tx}");
            true
        }
        Ok(_) => {
            return Err(invalid(
                "the trial transaction already has different contents",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(error),
    };
    let last = attempts::last(&directory, tx)?;
    if last.0 != 0 && !previously_recorded {
        return Err(invalid("orphaned durable trial attempt"));
    }
    if last.0 != 0 {
        if boot_next()?.is_some() {
            return Err(invalid("EFI BootNext already requests a boot"));
        }
        if !last.marked(&directory, tx, ".closed")? {
            last.mark(&directory, tx, ".closed")?;
        }
        if let Some(health) = prior_health(&directory, &approved, last)? {
            if dynamic && standing_promotion::commit(&directory, &raw, &health, &order)? {
                return Ok(ArmOutcome::RebootIntoTrial);
            }
            promotion::apply(
                &directory,
                &approved,
                text.as_bytes(),
                &health,
                active,
                &order,
            )?;
            return Ok(ArmOutcome::ContinueBoot);
        }
    }
    if !dynamic && previously_recorded {
        return Ok(ArmOutcome::ContinueBoot);
    }
    if last.0 == attempts::LIMIT {
        let pending = directory.join(PENDING);
        if read_record(&pending)? == raw {
            fs::remove_file(pending)?;
            File::open(&directory)?.sync_all()?;
        }
        println!("FVCA_TRIAL_ATTEMPTS_EXHAUSTED {tx} {}", last.0);
        return Ok(ArmOutcome::ContinueBoot);
    }
    if boot_next()?.is_some() {
        return Err(invalid("EFI BootNext already requests a boot"));
    }
    if let Some(standing) = &standing {
        standing::require_fresh(standing)?;
        watchdog::require_available()?;
    }
    if last.0 == 0 {
        verify_candidate_esp(&approved)?;
    }
    if let Some(standing) = &standing {
        standing::verify_candidate(standing)?;
        standing::require_fresh(standing)?;
    }

    // Consume the signed authorization durably before asking firmware for the one-shot trial.
    if !previously_recorded {
        publish(&record, &raw)?;
    }
    let attempt = attempts::Attempt(last.0 + 1);
    attempt.mark(&directory, tx, "")?;
    crate::run(Command::new("/usr/lib/fvca/set-boot-next").arg(trial.candidate.id.to_string()))?;
    if boot_next()? != Some(trial.candidate.id) {
        return Err(invalid(
            "firmware did not store the approved BootNext value",
        ));
    }
    attempt.mark(&directory, tx, ".armed")?;
    println!(
        "FVCA_TRIAL_ARMED {tx} {:04x} {}",
        trial.candidate.id, attempt.0
    );
    if dynamic {
        Ok(ArmOutcome::RebootIntoTrial)
    } else {
        Ok(ArmOutcome::ContinueBoot)
    }
}

fn boot_id() -> io::Result<String> {
    let id = fs::read_to_string(BOOT_ID)?;
    Ok(recovery::uuid(id.trim_end())?.to_owned())
}

fn candidate<'a>(cmdline: &str, raw: &'a mut Vec<u8>) -> io::Result<Option<Trial<'a>>> {
    let mut markers = cmdline
        .split_ascii_whitespace()
        .filter(|arg| arg.split('=').next() == Some(CANDIDATE_ARGUMENT));
    let marker = markers.next();
    *raw = match read(Path::new(CANDIDATE), 1024) {
        Err(error) if error.kind() == io::ErrorKind::NotFound && marker.is_none() => {
            return Ok(None);
        }
        result => result?,
    };
    let trial = candidate_selection(std::str::from_utf8(raw).map_err(io::Error::other)?)?;
    if markers.next().is_some()
        || marker.and_then(|arg| arg.split_once('=').map(|(_, id)| id)) != Some(trial.transaction)
    {
        return Err(invalid(
            "Hypervisor trial marker differs from the signed candidate policy",
        ));
    }
    Ok(Some(trial))
}

pub fn arm_candidate_watchdog(cmdline: &str) -> io::Result<()> {
    use fvca_trial_authorization::WATCHDOG_ARGUMENT;
    let signed = watchdog::policy()?;
    let mut markers = cmdline
        .split_ascii_whitespace()
        .filter(|arg| arg.split('=').next() == Some(WATCHDOG_ARGUMENT));
    let marker = markers.next();
    if marker
        != signed
            .map(|seconds| format!("{WATCHDOG_ARGUMENT}={seconds}"))
            .as_deref()
        || markers.next().is_some()
    {
        return Err(invalid(
            "UKI watchdog marker differs from the signed watchdog policy",
        ));
    }
    let Some(seconds) = signed else {
        if Path::new(CANDIDATE).try_exists()? && Path::new(TRIAL_KEY).try_exists()? {
            return Err(invalid(
                "standing trial candidate requires a signed watchdog deadline",
            ));
        }
        return Ok(());
    };
    let mut raw = Vec::new();
    let trial = candidate(cmdline, &mut raw)?
        .ok_or_else(|| invalid("trial watchdog requires a signed candidate"))?;
    let order = boot_order()?;
    if selected()? != trial.candidate.id || boot_next()?.is_some() {
        return Err(invalid(
            "watchdog requires the selected candidate and consumed BootNext",
        ));
    }
    if order.get(..2) == Some(&[trial.candidate.id, trial.stable.id]) {
        return Ok(());
    }
    if order.get(..2) != Some(&[trial.stable.id, trial.candidate.id]) {
        return Err(invalid("watchdog requires the authorized stable fallback"));
    }
    gpt_device(&trial.stable)?;
    watchdog::arm(seconds, &boot_id()?, trial.transaction)
}

pub fn stop_candidate_watchdog_for_firmware(cmdline: &str) -> io::Result<()> {
    if watchdog::policy()?.is_none() {
        return Ok(());
    }
    let mut raw = Vec::new();
    let trial = candidate(cmdline, &mut raw)?.ok_or_else(|| {
        invalid("firmware recovery requires the signed candidate watchdog identity")
    })?;
    watchdog::stop(&boot_id()?, trial.transaction)
}

pub fn start_candidate(
    cmdline: &str,
    slot: Option<&crate::hypervisor_slot::Slot>,
    guest: Option<&str>,
    active: &runtime::Activation,
    recovering: bool,
    epoch: Option<&str>,
) -> io::Result<()> {
    let mut raw = Vec::new();
    let Some(trial) = candidate(cmdline, &mut raw)? else {
        return Ok(());
    };
    let slot = slot.ok_or_else(|| invalid("trial candidate requires its verified GPT slot"))?;
    if recovering
        || slot.esp != trial.candidate.esp
        || selected()? != trial.candidate.id
        || boot_next()?.is_some()
        || Path::new(AUTHORIZATION).try_exists()?
    {
        return Err(invalid(
            "candidate boot does not match the authorized trial and stable recovery order",
        ));
    }
    let directory = record_directory()?;
    let order = boot_order()?;
    if order.first() == Some(&trial.candidate.id)
        || directory
            .join(format!("{}.promotion-confirmed", trial.transaction))
            .try_exists()?
    {
        return promotion::authorize_promoted(
            &directory,
            &trial,
            guest,
            active,
            &order,
            &slot.payload_ids,
        );
    }
    if order.first() != Some(&trial.stable.id) {
        return Err(invalid(
            "trial boot requires the stable slot first in EFI BootOrder",
        ));
    }
    let attempt = read_record(&directory.join(trial.transaction)).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            invalid("candidate trial has no recorded stable authorization")
        } else {
            error
        }
    })?;
    let number = attempts::last(&directory, trial.transaction)?;
    number.require_armed(&directory, trial.transaction)?;
    if number.marked(&directory, trial.transaction, ".closed")? {
        return Err(invalid("candidate trial attempt is already closed"));
    }
    let standing = Path::new(TRIAL_KEY)
        .try_exists()?
        .then(|| standing::verify(&attempt))
        .transpose()?;
    let text = match &standing {
        Some(standing) => {
            if !standing
                .payloads
                .as_flattened()
                .iter()
                .copied()
                .eq(slot.payload_ids.iter().map(String::as_str))
            {
                return Err(invalid("candidate payloads differ from the standing trial"));
            }
            standing::require_epoch(standing, epoch, standing.candidate_epoch)?;
            standing::require_fresh(standing)?;
            standing.attempt
        }
        None => std::str::from_utf8(&attempt).map_err(io::Error::other)?,
    };
    let approved = authorization(text)?;
    if trial != approved.trial
        || guest != Some(approved.guest)
        || active.core != approved.core
        || active.extension != approved.runtime
    {
        return Err(invalid(
            "candidate boot does not match the recorded trial composition",
        ));
    }
    gpt_device(&trial.stable)?;
    // The stable slot pins the installed ESP before arming. Firmware can update
    // FAT metadata during boot, so check the signed active tuple after handoff.
    gpt_device(&trial.candidate)?;

    let boot = boot_id()?;
    let record = format!(
        concat!(
            "FVCA-HYPERVISOR-TRIAL-HEALTH-1\ntransaction={}\nboot_id={}\n",
            "candidate={}\ncandidate_esp_sha256={}\ncore_root={}\nguest_bundle={}\nvm_runtime={}\n"
        ),
        trial.transaction,
        boot,
        trial.candidate.esp,
        approved.digest,
        active.core,
        approved.guest,
        active.extension
    );
    publish(
        &number.path(&directory, trial.transaction, ".started"),
        record.as_bytes(),
    )
    .map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            invalid("candidate trial already started on an earlier boot")
        } else {
            error
        }
    })?;
    promotion::record_candidate_key(&directory, trial.transaction)?;
    publish(Path::new(STARTED), record.as_bytes())?;
    if standing.is_some()
        && let Err(error) =
            standing_promotion::enroll_return(&directory, &trial, &attempt, &slot.payload_ids)
    {
        eprintln!("FVCA_STANDING_PROMOTION_REFUSED {error}");
    }
    let units = Path::new("/run/systemd/system");
    let requires = units.join("fvca-base.target.requires");
    fs::create_dir_all(&requires)?;
    fs::write(units.join("fvca-trial-health.service"), HEALTH_UNIT)?;
    std::os::unix::fs::symlink(
        "../fvca-trial-health.service",
        requires.join("fvca-trial-health.service"),
    )?;
    println!("FVCA_TRIAL_CANDIDATE_STARTED {} {boot}", trial.transaction);
    Ok(())
}

fn evidence(receipt: &[u8]) -> io::Result<Evidence<'_>> {
    let text = std::str::from_utf8(receipt).map_err(io::Error::other)?;
    let fields: Vec<_> = text.split('\n').collect();
    let [
        "FVCA-HYPERVISOR-TRIAL-HEALTH-1",
        transaction,
        boot,
        candidate,
        esp,
        core,
        guest,
        runtime,
        "",
    ] = fields.as_slice()
    else {
        return Err(invalid("malformed candidate readiness record"));
    };
    Ok(Evidence {
        transaction: identity(transaction, "transaction=", &[8, 4, 4, 4, 12], '-')?,
        boot: identity(boot, "boot_id=", &[8, 4, 4, 4, 12], '-')?,
        candidate: identity(candidate, "candidate=", &[8, 4, 4, 4, 12], '-')?,
        esp_digest: digest(esp, "candidate_esp_sha256=")?,
        core: digest(core, "core_root=")?,
        runtime: digest(runtime, "vm_runtime=")?,
        guest: digest(guest, "guest_bundle=")?,
    })
}

pub fn record_health() -> io::Result<()> {
    let receipt = read_record(Path::new(STARTED))?;
    let evidence = evidence(&receipt)?;
    let transaction = evidence.transaction;
    let launch = fs::read_to_string(crate::guest_boot::SELECTION)?;
    if evidence.boot != boot_id()? || crate::guest_boot::parse(&launch)?.bundle != evidence.guest {
        return Err(invalid(
            "candidate readiness record does not match this boot",
        ));
    }
    crate::run(Command::new("/usr/bin/systemctl").args([
        "--quiet",
        "is-active",
        "fvca-service-guest.service",
    ]))?;
    crate::run(
        Command::new("/usr/bin/findmnt")
            .args([
                "--mountpoint",
                HOST_DATA,
                "--types",
                "btrfs",
                "--options",
                "rw,nodev,nosuid,noexec",
            ])
            .stdout(Stdio::null()),
    )?;
    let directory = record_directory()?;
    let attempt = attempts::last(&directory, transaction)?;
    attempt.require_armed(&directory, transaction)?;
    if attempt.marked(&directory, transaction, ".closed")?
        || read_record(&attempt.path(&directory, transaction, ".started"))? != receipt
    {
        return Err(invalid(
            "durable candidate start differs from the current boot",
        ));
    }
    let healthy = directory.join(format!("{transaction}.healthy"));
    match read_record(&healthy) {
        Ok(prior) if prior == receipt => return Ok(()),
        Ok(_) => return Err(invalid("durable candidate health differs from this boot")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error),
    }
    watchdog::stop(evidence.boot, transaction)?;
    publish(&healthy, &receipt)?;
    println!("FVCA_TRIAL_HEALTH_RECORDED {transaction}");
    Ok(())
}
