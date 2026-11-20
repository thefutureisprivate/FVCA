use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use rustix::fs::{self as unix, OFlags};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{Result, invalid};

const GPT_LIMIT: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug)]
pub(super) struct Extent {
    pub start: u64,
    pub bytes: u64,
}

impl Extent {
    pub fn end(self) -> u64 {
        self.start + self.bytes
    }

    pub fn chunks(self, maximum: usize) -> impl Iterator<Item = (u64, usize)> {
        (self.start..self.end())
            .step_by(maximum)
            .map(move |offset| (offset, (self.end() - offset).min(maximum as u64) as usize))
    }
}

#[derive(Deserialize)]
struct Listing {
    partitiontable: Table,
}

#[derive(Deserialize)]
struct Table {
    label: String,
    id: String,
    unit: String,
    firstlba: u64,
    lastlba: u64,
    sectorsize: u64,
    partitions: Vec<Partition>,
}

#[derive(Deserialize)]
struct Partition {
    #[serde(rename = "type")]
    kind: String,
    uuid: String,
    start: u64,
    size: u64,
}

pub(super) struct Region {
    pub uuid: String,
    pub extent: Extent,
}

pub(super) struct Layout<const N: usize> {
    pub id: String,
    pub regions: [Region; N],
    prefix: Extent,
    suffix: Extent,
}

pub(super) struct Disk {
    pub file: File,
    pub bytes: u64,
    pub physical: bool,
}

pub(super) fn check_sector(sector: u64) -> io::Result<()> {
    if !matches!(sector, 512 | 4096) {
        return Err(invalid("logical sector size must be 512 or 4096 bytes"));
    }
    Ok(())
}

fn valid_uuid(uuid: &str) -> bool {
    uuid.len() == 36
        && uuid.as_bytes().iter().enumerate().all(|(i, byte)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                *byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
        && uuid != "00000000-0000-0000-0000-000000000000"
}

fn sys_number(directory: &Path, name: &str) -> Result<u64> {
    Ok(fs::read_to_string(directory.join(name))?.trim().parse()?)
}

impl Disk {
    pub fn open(path: &Path, sector: u64, write: bool) -> Result<Self> {
        check_sector(sector)?;
        let path = path.canonicalize()?;
        let before = path.metadata()?;
        let physical = before.file_type().is_block_device();
        let mut flags = OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY;
        if physical && path.starts_with("/dev") {
            // Claim the whole block device. Linux rejects this while a partition is in use.
            flags |= OFlags::EXCL;
        } else if !before.is_file() {
            return Err(invalid(
                "expected a whole NVMe namespace or a private disposable disk image",
            )
            .into());
        }
        let file = OpenOptions::new()
            .read(true)
            .write(write)
            .custom_flags(flags.bits() as i32)
            .open(path)?;
        let info = file.metadata()?;
        if info.ino() != before.ino()
            || info.dev() != before.dev()
            || info.rdev() != before.rdev()
            || info.file_type() != before.file_type()
        {
            return Err(invalid("disk changed while acquiring its maintenance lease").into());
        }
        file.try_lock().map_err(io::Error::other)?;
        let bytes = if physical {
            let number = info.rdev();
            let device = fs::canonicalize(format!(
                "/sys/dev/block/{}:{}",
                unix::major(number),
                unix::minor(number)
            ))?;
            if device.join("partition").exists()
                || !device
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("nvme"))
                || sys_number(&device.join("queue"), "logical_block_size")? != sector
            {
                return Err(invalid(
                    "the whole NVMe namespace must use the reviewed logical sector size",
                )
                .into());
            }
            sys_number(&device, "size")?
                .checked_mul(512)
                .ok_or_else(|| invalid("disk capacity overflow"))?
        } else {
            if info.nlink() != 1
                || info.mode() & 0o7777 != 0o600
                || info.uid() != rustix::process::geteuid().as_raw()
            {
                return Err(invalid("disposable disk images must be owned by this account with mode 0600 and one link").into());
            }
            info.len()
        };
        Ok(Self {
            file,
            bytes,
            physical,
        })
    }
}

pub(super) fn fd_path(file: &File) -> PathBuf {
    PathBuf::from(format!(
        "/proc/{}/fd/{}",
        std::process::id(),
        file.as_raw_fd()
    ))
}

fn sfdisk(file: &File, sector: u64, action: &str) -> Result<Vec<u8>> {
    // Use the held inode for both inspection and I/O, including when an NVMe by-id link was supplied.
    let output = Command::new("/usr/bin/sfdisk")
        .env_clear()
        .args([action, "--sector-size", &sector.to_string()])
        .arg(fd_path(file))
        .output()?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(invalid("sfdisk did not accept the disk's GPT").into());
    }
    Ok(output.stdout)
}

impl<const N: usize> Layout<N> {
    pub fn read(file: &File, size: u64, sector: u64, types: [&str; N]) -> Result<Self> {
        if !size.is_multiple_of(sector) {
            return Err(invalid("disk capacity is not aligned to its logical sectors").into());
        }
        sfdisk(file, sector, "--verify")?;
        let table =
            serde_json::from_slice::<Listing>(&sfdisk(file, sector, "--json")?)?.partitiontable;
        if table.label != "gpt"
            || table.unit != "sectors"
            || table.sectorsize != sector
            || !valid_uuid(&table.id)
            || table.partitions.len() != N
        {
            return Err(invalid("unexpected partition set or geometry").into());
        }
        let last_sector = size / sector;
        let tail = table
            .lastlba
            .checked_add(1)
            .ok_or_else(|| invalid("invalid GPT boundary"))?;
        if table.firstlba < 2
            || table.firstlba >= tail
            || tail >= last_sector
            || table.firstlba > GPT_LIMIT / sector
            || last_sector - tail > GPT_LIMIT / sector
        {
            return Err(
                invalid("GPT usable sectors are outside the disk or metadata bounds").into(),
            );
        }
        let prefix = Extent {
            start: 0,
            bytes: table.firstlba * sector,
        };
        let suffix = Extent {
            start: tail * sector,
            bytes: size - tail * sector,
        };
        let mut parts = table.partitions;
        parts.sort_unstable_by_key(|part| part.start);
        let mut end = table.firstlba;
        let mut uuids = HashSet::new();
        for part in &parts {
            if part.size == 0
                || part.start < end
                || part.start >= tail
                || part.size > tail - part.start
                || !valid_uuid(&part.uuid)
                || !uuids.insert(part.uuid.to_ascii_lowercase())
            {
                return Err(invalid(
                    "GPT partitions overlap, repeat an identity or exceed the usable sectors",
                )
                .into());
            }
            end = part.start + part.size;
        }
        let regions: Vec<_> = types
            .into_iter()
            .map(|kind| {
                let index = parts
                    .iter()
                    .position(|part| part.kind.eq_ignore_ascii_case(kind))
                    .ok_or_else(|| invalid("missing required partition type"))?;
                let part = parts.swap_remove(index);
                Ok(Region {
                    uuid: part.uuid.to_ascii_lowercase(),
                    extent: Extent {
                        start: part.start * sector,
                        bytes: part.size * sector,
                    },
                })
            })
            .collect::<io::Result<_>>()?;
        Ok(Self {
            id: table.id.to_ascii_lowercase(),
            regions: regions
                .try_into()
                .map_err(|_| invalid("incomplete GPT partition set"))?,
            prefix,
            suffix,
        })
    }

    pub fn fingerprint(&self, disk: &Disk, sector: u64) -> io::Result<String> {
        let mut hash = Sha256::new();
        hash.update(b"FVCA-HYPERVISOR-GPT-1\0");
        for number in [sector, disk.bytes, self.prefix.bytes, self.suffix.start] {
            hash.update(number.to_le_bytes());
        }
        for extent in [self.prefix, self.suffix] {
            let mut bytes = vec![0; extent.bytes as usize];
            disk.file.read_exact_at(&mut bytes, extent.start)?;
            hash.update(bytes);
        }
        Ok(hex::encode(hash.finalize()))
    }
}
