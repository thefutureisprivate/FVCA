use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::os::unix::fs::FileExt;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use gpt::GptConfig;
use gpt::disk::LogicalBlockSize::Lb512;
use gpt::header::read_header_from_arbitrary_device;
use gpt::partition::{Partition, file_read_partitions};
use openssl::x509::X509;
use serde::Deserialize;

use crate::records::{Authorization, Derivation};
use crate::{Result, SIGNATURE_LIMIT, digest_stream, invalid, verify_signature};

const SECTOR: u64 = 512;
const ALIGNMENT: u64 = 1024 * 1024;
const TYPE_ROOT: &str = "4f68bce3-e8cd-4db1-96e7-fbcaf984b709";
const TYPE_VERITY: &str = "2c7357ed-ebd2-46d9-aec1-23d437ec2bf5";
const TYPE_SIGNATURE: &str = "41092b05-9fc8-4523-994f-2def0408b176";

pub struct Region {
    pub offset: u64,
    pub size: u64,
}

pub struct Image {
    pub root: Region,
    pub verity: Region,
    pub signature: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Seal {
    root_hash: String,
    certificate_fingerprint: String,
    signature: String,
}

fn region(partition: &Partition, kind: &str, name: &str, offset: u64, size: u64) -> Result<Region> {
    if partition.part_type_guid.guid.as_hyphenated().to_string() != kind
        || partition.name != name
        || partition.flags != 0
        || partition.first_lba != offset / SECTOR
        || partition.last_lba.checked_add(1) != Some((offset + size) / SECTOR)
    {
        return Err(invalid(
            "GPT partition does not match the authorized workload layout",
        ));
    }
    Ok(Region { offset, size })
}

pub(crate) fn verify_image(
    file: &mut File,
    authorization: &Authorization,
    derivation: &Derivation,
    certificate: &X509,
) -> Result<Image> {
    let root_offset = ALIGNMENT;
    let verity_offset = (root_offset + derivation.root.size).next_multiple_of(ALIGNMENT);
    let signature_offset =
        (verity_offset + derivation.verity_tree.size).next_multiple_of(ALIGNMENT);
    let disk_size = (signature_offset + SIGNATURE_LIMIT).next_multiple_of(ALIGNMENT) + ALIGNMENT;
    if disk_size != authorization.artifact.size {
        return Err(invalid("invalid workload GPT disk size"));
    }

    // Pin the table shape before parsing entries. The GPT parser assumes 128-byte entries.
    let primary = read_header_from_arbitrary_device(file, Lb512)?;
    let last_lba = disk_size / SECTOR - 1;
    if primary.header_size_le != 92
        || primary.reserved != 0
        || primary.current_lba != 1
        || primary.backup_lba != last_lba
        || primary.first_usable != ALIGNMENT / SECTOR
        || primary.last_usable != last_lba - 33
        || primary.part_start != 2
        || primary.num_parts != 128
        || primary.part_size != 128
    {
        return Err(invalid("invalid primary workload GPT geometry"));
    }
    let mut disk = GptConfig::new()
        .logical_block_size(Lb512)
        .only_valid_headers(true)
        .open_from_device(&mut *file)?;
    let backup = disk.backup_header()?.clone();
    let partitions = disk.take_partitions();
    if backup.header_size_le != primary.header_size_le
        || backup.reserved != 0
        || backup.disk_guid != primary.disk_guid
        || backup.current_lba != last_lba
        || backup.backup_lba != 1
        || backup.first_usable != primary.first_usable
        || backup.last_usable != primary.last_usable
        || backup.part_start != last_lba - 32
        || backup.num_parts != primary.num_parts
        || backup.part_size != primary.part_size
        || backup.crc32_parts != primary.crc32_parts
        || file_read_partitions(file, &backup, Lb512)? != partitions
        || !partitions.keys().copied().eq(1..=3)
    {
        return Err(invalid("invalid backup or extra workload GPT entries"));
    }
    let root = region(
        &partitions[&1],
        TYPE_ROOT,
        "root",
        root_offset,
        derivation.root.size,
    )?;
    let verity = region(
        &partitions[&2],
        TYPE_VERITY,
        "verity",
        verity_offset,
        derivation.verity_tree.size,
    )?;
    let signed = region(
        &partitions[&3],
        TYPE_SIGNATURE,
        "signature",
        signature_offset,
        SIGNATURE_LIMIT,
    )?;
    let hash = &authorization.verity_root_hash;
    let (root_id, verity_id) = hash.split_at(32);
    if partitions[&1].part_guid.as_simple().to_string() != root_id
        || partitions[&2].part_guid.as_simple().to_string() != verity_id
    {
        return Err(invalid(
            "workload GPT identities do not bind the verity root hash",
        ));
    }
    let mut bytes = vec![0; signed.size as usize];
    file.read_exact_at(&mut bytes, signed.offset)?;
    let end = bytes
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |index| index + 1);
    let seal: Seal = serde_json::from_slice(&bytes[..end])?;
    if seal.root_hash != *hash
        || authorization.workload_certificate.strip_prefix("sha256:")
            != Some(seal.certificate_fingerprint.as_str())
    {
        return Err(invalid(
            "verity signature does not bind the authorized workload root and signer",
        ));
    }
    let signature = STANDARD.decode(&seal.signature)?;
    verify_signature(hash.as_bytes(), &signature, certificate)?;
    for (region, expected) in [
        (&root, &derivation.root),
        (&verity, &derivation.verity_tree),
    ] {
        file.seek(SeekFrom::Start(region.offset))?;
        if digest_stream(&mut *file, region.size)? != expected.digest {
            return Err(invalid(
                "workload partition does not match its signed derivation digest",
            ));
        }
    }
    file.rewind()?;
    Ok(Image {
        root,
        verity,
        signature,
    })
}
