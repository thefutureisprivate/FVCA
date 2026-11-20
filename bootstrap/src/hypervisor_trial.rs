//! Arm one authorized UEFI BootNext attempt without changing the recovery order.

use std::collections::BTreeSet;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{find_partition, identity, invalid, recovery, runtime, sys_block};

const AUTHORIZATION: &str = "/usr/lib/fvca/hypervisor-trial";
const HOST_DATA: &str = "/run/fvca/host-data";
const EFI: &str = "/sys/firmware/efi/efivars";
const EFI_GLOBAL: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
const LOADER: &str = "\\EFI\\BOOT\\BOOTX64.EFI";
const ATTRIBUTES: u32 = 7;
const O_NONBLOCK: i32 = 0o4000;
const O_NOFOLLOW: i32 = 0o400000;

struct Entry<'a> {
    id: u16,
    esp: &'a str,
}

struct Authorization<'a> {
    transaction: &'a str,
    stable: Entry<'a>,
    candidate: Entry<'a>,
    digest: &'a str,
    bytes: u64,
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

fn authorization(text: &str) -> io::Result<Authorization<'_>> {
    let fields: Vec<_> = text.split('\n').collect();
    let [
        "FVCA-HYPERVISOR-TRIAL-1",
        transaction,
        stable,
        candidate,
        digest,
        bytes,
        "",
    ] = fields.as_slice()
    else {
        return Err(invalid("invalid Hypervisor trial authorization"));
    };
    let transaction = identity(transaction, "transaction=", &[8, 4, 4, 4, 12], '-')?;
    let stable = entry(stable, "stable=")?;
    let candidate = entry(candidate, "candidate=")?;
    let digest = runtime::hash(
        digest
            .strip_prefix("candidate_esp_sha256=")
            .ok_or_else(|| invalid("missing candidate ESP digest"))?,
    )?;
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
    if stable.id == candidate.id || stable.esp == candidate.esp {
        return Err(invalid(
            "stable and candidate boot entries must be distinct",
        ));
    }
    Ok(Authorization {
        transaction,
        stable,
        candidate,
        digest,
        bytes,
    })
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
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(invalid("boot trial record is not a private Host file"));
    }
    bounded_read(file, 1024)
}

pub fn arm_if_authorized(current_esp: Option<&str>) -> io::Result<()> {
    let raw = match read(Path::new(AUTHORIZATION), 1024) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
        Ok(raw) => raw,
    };
    let text = std::str::from_utf8(&raw).map_err(io::Error::other)?;
    let approved = authorization(text)?;
    if current_esp != Some(approved.stable.esp)
        || selected()? != approved.stable.id
        || boot_order()?.first() != Some(&approved.stable.id)
    {
        return Err(invalid(
            "the signed stable slot must be booted and first in EFI BootOrder",
        ));
    }
    gpt_device(&approved.stable)?;
    let directory = record_directory()?;
    let record = directory.join(approved.transaction);
    match read_record(&record) {
        Ok(prior) if prior == raw => {
            println!("FVCA_TRIAL_PREVIOUSLY_RECORDED {}", approved.transaction);
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
    let (candidate, size) = gpt_device(&approved.candidate)?;
    if size != approved.bytes || recovery::sha256(File::open(candidate)?)? != approved.digest {
        return Err(invalid("candidate ESP differs from the approved image"));
    }

    // Consume the signed authorization durably before asking firmware for the one-shot trial.
    let mut marker = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(record)
        .map_err(|error| {
            io::Error::other(format!("cannot create the boot trial record: {error}"))
        })?;
    marker.write_all(&raw)?;
    marker.sync_all()?;
    File::open(directory)?.sync_all()?;
    crate::run(Command::new("/usr/lib/fvca/set-boot-next").arg(approved.candidate.id.to_string()))?;
    if boot_next()? != Some(approved.candidate.id) {
        return Err(invalid(
            "firmware did not store the approved BootNext value",
        ));
    }
    println!(
        "FVCA_TRIAL_ARMED {} {:04x}",
        approved.transaction, approved.candidate.id
    );
    Ok(())
}
