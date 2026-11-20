//! Shared EFI load option validation for Host trials and capsule delivery.

use std::collections::BTreeSet;
use std::io;

use crate::{invalid, uuid};

pub const GLOBAL: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
pub const FIRMWARE_ESP: &str = "/run/fvca/firmware-esp-device-path";

pub fn variable_data(bytes: &[u8], attributes: u32) -> io::Result<&[u8]> {
    let (header, data) = bytes
        .split_at_checked(4)
        .ok_or_else(|| invalid("truncated EFI variable"))?;
    if header != attributes.to_le_bytes() {
        return Err(invalid("unexpected EFI variable attributes"));
    }
    Ok(data)
}

pub fn boot_order(value: &[u8]) -> io::Result<Vec<u16>> {
    let (words, remainder) = value.as_chunks::<2>();
    let order: Vec<_> = words.iter().copied().map(u16::from_le_bytes).collect();
    let unique: BTreeSet<_> = order.iter().collect();
    if !remainder.is_empty() || order.is_empty() || order.len() > 128 || unique.len() != order.len()
    {
        return Err(invalid("malformed EFI BootOrder"));
    }
    Ok(order)
}

pub fn esp_device_path(
    esp: &str,
    partition_index: u32,
    start_lba: u64,
    size_lba: u64,
) -> io::Result<Vec<u8>> {
    if partition_index == 0
        || start_lba == 0
        || size_lba == 0
        || start_lba.checked_add(size_lba).is_none()
    {
        return Err(invalid("invalid EFI System Partition geometry"));
    }
    let mut guid = [0u8; 16];
    let mut offset = 0;
    for group in uuid(esp)?.split('-') {
        for index in (0..group.len()).step_by(2) {
            guid[offset] =
                u8::from_str_radix(&group[index..index + 2], 16).map_err(io::Error::other)?;
            offset += 1;
        }
    }
    if guid == [0; 16] {
        return Err(invalid("EFI System Partition UUID is zero"));
    }
    guid[..4].reverse();
    guid[4..6].reverse();
    guid[6..8].reverse();
    let mut path = vec![4, 1, 42, 0];
    path.extend_from_slice(&partition_index.to_le_bytes());
    path.extend_from_slice(&start_lba.to_le_bytes());
    path.extend_from_slice(&size_lba.to_le_bytes());
    path.extend_from_slice(&guid);
    path.extend_from_slice(&[2, 2]);

    let loader: Vec<_> = "\\EFI\\BOOT\\BOOTX64.EFI"
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect();
    path.extend_from_slice(&[4, 4]);
    path.extend_from_slice(
        &u16::try_from(4 + loader.len())
            .expect("fixed EFI loader name fits in a device path node")
            .to_le_bytes(),
    );
    path.extend_from_slice(&loader);
    path.extend_from_slice(&[0x7f, 0xff, 4, 0]);
    Ok(path)
}

pub fn require_esp_load_option(raw: &[u8], expected: &[u8]) -> io::Result<()> {
    let header = raw
        .first_chunk::<6>()
        .ok_or_else(|| invalid("truncated EFI load option"))?;
    if header[..4] != 1u32.to_le_bytes() {
        return Err(invalid(
            "EFI load option must be an active application boot entry",
        ));
    }
    let description = raw[6..]
        .as_chunks::<2>()
        .0
        .iter()
        .position(|word| *word == [0, 0])
        .filter(|length| *length != 0)
        .ok_or_else(|| invalid("invalid EFI boot entry description"))?;
    let path = &raw[6 + 2 * (description + 1)..];
    if path.len() != usize::from(u16::from_le_bytes([header[4], header[5]])) {
        return Err(invalid(
            "EFI boot entry must have no optional load parameters",
        ));
    }
    if expected.is_empty() || path != expected {
        return Err(invalid(
            "EFI load option does not match the authorized ESP and loader",
        ));
    }
    Ok(())
}
