//! Arm and observe one authorized Hypervisor candidate boot.

use std::collections::BTreeSet;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::{find_partition, identity, invalid, recovery, runtime, sys_block};

mod promotion;

pub const PROMOTION_KEY: &str = "/usr/lib/fvca/hypervisor-promotion-key";
pub const PROMOTION_LIMIT: usize = 2048;
const AUTHORIZATION: &str = "/usr/lib/fvca/hypervisor-trial";
const CANDIDATE: &str = "/usr/lib/fvca/hypervisor-trial-candidate";
const BOOT_ID: &str = "/proc/sys/kernel/random/boot_id";
const STARTED: &str = "/run/fvca/boot-trial-started";
const HOST_DATA: &str = "/run/fvca/host-data";
const EFI: &str = "/sys/firmware/efi/efivars";
const EFI_GLOBAL: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
const LOADER: &str = "\\EFI\\BOOT\\BOOTX64.EFI";
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

#[derive(PartialEq, Eq)]
struct Entry<'a> {
    id: u16,
    esp: &'a str,
}

#[derive(PartialEq, Eq)]
struct Trial<'a> {
    transaction: &'a str,
    stable: Entry<'a>,
    candidate: Entry<'a>,
}

struct Authorization<'a> {
    trial: Trial<'a>,
    digest: &'a str,
    bytes: u64,
    core: &'a str,
    runtime: &'a str,
    guest: &'a str,
}

struct Evidence<'a> {
    transaction: &'a str,
    boot: &'a str,
    candidate: &'a str,
    esp_digest: &'a str,
    core: &'a str,
    guest: &'a str,
    runtime: &'a str,
}

fn entry<'a>(line: &'a str, field: &str) -> io::Result<Entry<'a>> {
    let (id, esp) = line
        .strip_prefix(field)
        .and_then(|value| value.split_once(','))
        .ok_or_else(|| invalid("invalid trial boot entry"))?;
    identity(id, "", &[4], '-')?;
    let id = u16::from_str_radix(id, 16).map_err(io::Error::other)?;
    Ok(Entry {
        id,
        esp: recovery::uuid(esp)?,
    })
}

fn trial<'a>(transaction: &'a str, stable: &'a str, candidate: &'a str) -> io::Result<Trial<'a>> {
    let transaction = identity(transaction, "transaction=", &[8, 4, 4, 4, 12], '-')?;
    let stable = entry(stable, "stable=")?;
    let candidate = entry(candidate, "candidate=")?;
    if stable.id == candidate.id || stable.esp == candidate.esp {
        return Err(invalid(
            "stable and candidate boot entries must be distinct",
        ));
    }
    Ok(Trial {
        transaction,
        stable,
        candidate,
    })
}

fn digest<'a>(line: &'a str, field: &str) -> io::Result<&'a str> {
    runtime::hash(
        line.strip_prefix(field)
            .ok_or_else(|| invalid("missing trial digest"))?,
    )
}

fn authorization(text: &str) -> io::Result<Authorization<'_>> {
    let fields: Vec<_> = text.split('\n').collect();
    let [
        "FVCA-HYPERVISOR-TRIAL-2",
        transaction,
        stable,
        candidate,
        esp,
        bytes,
        core,
        vm_runtime,
        guest,
        "",
    ] = fields.as_slice()
    else {
        return Err(invalid("invalid Hypervisor trial authorization"));
    };
    let bytes = bytes
        .strip_prefix("candidate_esp_bytes=")
        .and_then(|value| {
            value
                .parse::<u64>()
                .ok()
                .filter(|bytes| bytes.to_string() == value)
        })
        .filter(|bytes| {
            (4096..=4 * 1024 * 1024 * 1024).contains(bytes) && bytes.is_multiple_of(4096)
        })
        .ok_or_else(|| invalid("invalid candidate ESP size"))?;
    Ok(Authorization {
        trial: trial(transaction, stable, candidate)?,
        digest: digest(esp, "candidate_esp_sha256=")?,
        bytes,
        core: digest(core, "candidate_core=")?,
        runtime: digest(vm_runtime, "candidate_runtime=")?,
        guest: digest(guest, "guest_bundle=")?,
    })
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
    Path::new(EFI).join(format!("{name}-{EFI_GLOBAL}"))
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
    let (header, data) = bytes
        .split_at_checked(4)
        .ok_or_else(|| invalid("truncated EFI variable"))?;
    if header != attributes.to_le_bytes() {
        return Err(invalid("unexpected EFI variable attributes"));
    }
    Ok(data.to_owned())
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
    let value = efi_data("BootOrder", ATTRIBUTES)?;
    let (words, remainder) = value.as_chunks::<2>();
    let order: Vec<_> = words.iter().copied().map(u16::from_le_bytes).collect();
    let unique: BTreeSet<_> = order.iter().collect();
    if !remainder.is_empty() || order.is_empty() || order.len() > 128 || unique.len() != order.len()
    {
        return Err(invalid("malformed EFI BootOrder"));
    }
    Ok(order)
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

fn gpt_device(entry: &Entry<'_>) -> io::Result<(PathBuf, u64)> {
    let device =
        find_partition(entry.esp)?.ok_or_else(|| invalid("authorized trial ESP is missing"))?;
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

    let raw = efi_data(&format!("Boot{:04X}", entry.id), ATTRIBUTES)?;
    let header = raw
        .first_chunk::<6>()
        .ok_or_else(|| invalid("truncated EFI load option"))?;
    if header[..4] != 1u32.to_le_bytes() {
        return Err(invalid(
            "trial EFI load option must be an active application boot entry",
        ));
    }
    let path_bytes = usize::from(u16::from_le_bytes([header[4], header[5]]));
    let description = raw[6..]
        .as_chunks::<2>()
        .0
        .iter()
        .position(|word| *word == [0, 0])
        .filter(|length| *length != 0)
        .ok_or_else(|| invalid("invalid EFI boot entry description"))?;
    let path = &raw[6 + 2 * (description + 1)..];
    if path.len() != path_bytes {
        return Err(invalid(
            "EFI boot entry must have no optional load parameters",
        ));
    }

    let mut guid = [0u8; 16];
    let mut offset = 0;
    for group in entry.esp.split('-') {
        for index in (0..group.len()).step_by(2) {
            guid[offset] =
                u8::from_str_radix(&group[index..index + 2], 16).map_err(io::Error::other)?;
            offset += 1;
        }
    }
    guid[..4].reverse();
    guid[4..6].reverse();
    guid[6..8].reverse();
    let mut expected = vec![4, 1, 42, 0];
    expected.extend_from_slice(&partition_index.to_le_bytes());
    expected.extend_from_slice(&(start / sectors_per_block).to_le_bytes());
    expected.extend_from_slice(&(size / sectors_per_block).to_le_bytes());
    expected.extend_from_slice(&guid);
    expected.extend_from_slice(&[2, 2]);
    let loader: Vec<_> = LOADER
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect();
    expected.extend_from_slice(&[4, 4]);
    expected.extend_from_slice(
        &(u16::try_from(4 + loader.len()).map_err(io::Error::other)?).to_le_bytes(),
    );
    expected.extend_from_slice(&loader);
    expected.extend_from_slice(&[0x7f, 0xff, 4, 0]);
    if path != expected {
        return Err(invalid(
            "EFI load option does not match the authorized ESP and loader",
        ));
    }
    Ok((
        device,
        size.checked_mul(512)
            .ok_or_else(|| invalid("trial ESP size overflow"))?,
    ))
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
    bounded_read(file, PROMOTION_LIMIT)
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

fn verify_arming(directory: &Path, id: &str, attempt: &[u8]) -> io::Result<()> {
    let armed = read_record(&directory.join(format!("{id}.armed"))).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            invalid("candidate trial has no verified firmware arming record")
        } else {
            error
        }
    })?;
    if armed != attempt {
        return Err(invalid(
            "firmware arming differs from the recorded trial authorization",
        ));
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
    attempt: &[u8],
) -> io::Result<Option<Vec<u8>>> {
    let id = approved.trial.transaction;
    let receipt = match read_record(&directory.join(format!("{id}.healthy"))) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        prior => prior?,
    };
    verify_arming(directory, id, attempt)?;
    let evidence = approved_evidence(approved, &receipt)?;
    if read_record(&directory.join(format!("{id}.started")))? != receipt {
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
) -> io::Result<()> {
    let raw = match read(Path::new(AUTHORIZATION), 1024) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
        Ok(raw) => raw,
    };
    let text = std::str::from_utf8(&raw).map_err(io::Error::other)?;
    let approved = authorization(text)?;
    let trial = &approved.trial;
    if guest != Some(approved.guest) {
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
        return Ok(());
    }
    if order.first() != Some(&trial.stable.id) {
        return Err(invalid(
            "the signed stable slot must be booted and first in EFI BootOrder",
        ));
    }
    let directory = record_directory()?;
    let record = directory.join(trial.transaction);
    match read_record(&record) {
        Ok(prior) if prior == raw => {
            println!("FVCA_TRIAL_PREVIOUSLY_RECORDED {}", trial.transaction);
            if let Some(health) = prior_health(&directory, &approved, &raw)? {
                promotion::apply(&directory, &approved, &raw, &health, active, &order)?;
            }
            return Ok(());
        }
        Ok(_) => {
            return Err(invalid(
                "the trial transaction already has different contents",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error),
    }
    if boot_next()?.is_some() {
        return Err(invalid("EFI BootNext already requests a boot"));
    }
    verify_candidate_esp(&approved)?;

    // Consume the signed authorization durably before asking firmware for the one-shot trial.
    publish(&record, &raw).map_err(|error| {
        io::Error::other(format!("cannot create the boot trial record: {error}"))
    })?;
    crate::run(Command::new("/usr/lib/fvca/set-boot-next").arg(trial.candidate.id.to_string()))?;
    if boot_next()? != Some(trial.candidate.id) {
        return Err(invalid(
            "firmware did not store the approved BootNext value",
        ));
    }
    publish(
        &directory.join(format!("{}.armed", trial.transaction)),
        &raw,
    )?;
    println!(
        "FVCA_TRIAL_ARMED {} {:04x}",
        trial.transaction, trial.candidate.id
    );
    Ok(())
}

fn boot_id() -> io::Result<String> {
    let id = fs::read_to_string(BOOT_ID)?;
    Ok(recovery::uuid(id.trim_end())?.to_owned())
}

pub fn start_candidate(
    slot: Option<&crate::hypervisor_slot::Slot>,
    guest: Option<&str>,
    active: &runtime::Activation,
    recovering: bool,
) -> io::Result<()> {
    let raw = match read(Path::new(CANDIDATE), 1024) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
        Ok(raw) => raw,
    };
    let trial = candidate_selection(std::str::from_utf8(&raw).map_err(io::Error::other)?)?;
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
    if order.first() == Some(&trial.candidate.id) {
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
    verify_arming(&directory, trial.transaction, &attempt)?;
    let approved = authorization(std::str::from_utf8(&attempt).map_err(io::Error::other)?)?;
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
        &directory.join(format!("{}.started", trial.transaction)),
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
    if read_record(&directory.join(format!("{transaction}.started")))? != receipt {
        return Err(invalid(
            "durable candidate start differs from the current boot",
        ));
    }
    let healthy = directory.join(format!("{transaction}.healthy"));
    match publish(&healthy, &receipt) {
        Err(error)
            if error.kind() == io::ErrorKind::AlreadyExists
                && read_record(&healthy)? == receipt => {}
        result => result?,
    }
    println!("FVCA_TRIAL_HEALTH_RECORDED {transaction}");
    Ok(())
}
