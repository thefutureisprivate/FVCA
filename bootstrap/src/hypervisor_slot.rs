//! Locate the immutable parts of one UKI-authorized Hypervisor GPT slot.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use crate::{find_partition, identity, invalid, sys_block};

const MANIFEST: &str = "/usr/lib/fvca/hypervisor-slot";
const FIELDS: [&str; 7] = [
    "esp=",
    "core=",
    "core_verity=",
    "runtime=",
    "runtime_verity=",
    "guest=",
    "guest_verity=",
];
const UUID: &[usize] = &[8, 4, 4, 4, 12];

pub struct Slot {
    pub esp: String,
    pub runtime: (PathBuf, PathBuf),
    pub guest: (PathBuf, PathBuf),
    pub payload_ids: [String; 6],
}

fn parse(manifest: &str) -> io::Result<[&str; 7]> {
    let mut lines = manifest.split('\n');
    if lines.next() != Some("FVCA-HYPERVISOR-SLOT-1") {
        return Err(invalid("invalid Hypervisor GPT slot selection version"));
    }
    let mut uuids = [""; 7];
    let mut unique = BTreeSet::new();
    for (uuid, field) in uuids.iter_mut().zip(FIELDS) {
        *uuid = identity(
            lines
                .next()
                .ok_or_else(|| invalid("missing slot partition"))?,
            field,
            UUID,
            '-',
        )?;
        if !unique.insert(*uuid) {
            return Err(invalid("Hypervisor slot partition UUIDs must be distinct"));
        }
    }
    if lines.next() != Some("") || lines.next().is_some() {
        return Err(invalid("extra Hypervisor slot fields"));
    }
    Ok(uuids)
}

fn discover(uuids: [&str; 7]) -> io::Result<[PathBuf; 7]> {
    let deadline = Instant::now() + Duration::from_secs(12);
    let mut paths = [const { PathBuf::new() }; 7];
    for (uuid, path) in uuids.into_iter().zip(&mut paths) {
        loop {
            if let Some(device) = find_partition(uuid)? {
                *path = device;
                break;
            }
            if Instant::now() >= deadline {
                return Err(invalid(
                    "authorized Hypervisor slot partitions are incomplete",
                ));
            }
            thread::sleep(Duration::from_millis(200));
        }
    }
    Ok(paths)
}

fn verify_layout(paths: &[PathBuf; 7]) -> io::Result<()> {
    let partitions = paths
        .iter()
        .map(|path| sys_block(path))
        .collect::<io::Result<Vec<_>>>()?;
    let disk = partitions[0]
        .parent()
        .ok_or_else(|| invalid("slot ESP has no parent disk"))?;
    for partition in &partitions {
        if partition.parent() != Some(disk) || !partition.join("partition").try_exists()? {
            return Err(invalid(
                "Hypervisor slot partitions must reside on one GPT disk",
            ));
        }
    }
    let mapping = sys_block(&fs::canonicalize(Path::new("/dev/mapper/root"))?)?;
    let slaves = fs::read_dir(mapping.join("slaves"))?
        .map(|entry| fs::canonicalize(entry?.path()))
        .collect::<io::Result<BTreeSet<_>>>()?;
    let expected = BTreeSet::from([partitions[1].clone(), partitions[2].clone()]);
    if slaves != expected {
        return Err(invalid(
            "mounted verity root uses partitions outside the authorized slot",
        ));
    }
    Ok(())
}

impl Slot {
    pub fn load() -> io::Result<Option<Self>> {
        let manifest = match fs::read_to_string(MANIFEST) {
            Ok(manifest) => manifest,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if manifest.len() > 1024 {
            return Err(invalid("Hypervisor slot selection is too large"));
        }
        let uuids = parse(&manifest)?;
        let paths = discover(uuids)?;
        verify_layout(&paths)?;
        let [_, _, _, runtime, runtime_verity, guest, guest_verity] = paths;
        println!("FVCA_HYPERVISOR_SLOT_VERIFIED {}", uuids[0]);
        Ok(Some(Self {
            esp: uuids[0].to_owned(),
            runtime: (runtime, runtime_verity),
            guest: (guest, guest_verity),
            payload_ids: std::array::from_fn(|index| uuids[index + 1].to_owned()),
        }))
    }
}
