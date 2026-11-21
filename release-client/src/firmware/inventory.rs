//! Sanitize and page the live device list from the confined Host fwupd peer.

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use super::{Devices, ObservedDevice, has, label, live, lower_hex, uuid};
use crate::{Result, channel::digest, invalid, valid_digest};

pub(crate) const READER_UID: u32 = 62001;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InventoryCursor {
    generation_sha256: String,
    after: String,
}

impl InventoryCursor {
    pub(crate) fn valid(&self) -> bool {
        valid_digest(&self.generation_sha256) && lower_hex(&self.after, 40)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InventoryPage {
    fwupd_version: String,
    checked_at: i64,
    generation_sha256: String,
    device: Option<Device>,
    next: Option<InventoryCursor>,
}

#[derive(Deserialize, Serialize)]
#[serde(
    tag = "result",
    content = "inventory",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub(crate) enum InventoryReply {
    Page(Box<InventoryPage>),
    Changed,
    InvalidCursor,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Device {
    device_id: String,
    plugin: String,
    name: Option<String>,
    guids: Vec<String>,
    protocols: Vec<String>,
    vendor_ids: Vec<String>,
    installed_version: Option<String>,
    installed_version_raw: Option<u64>,
    version_format: Option<String>,
    updatable: bool,
    inhibited: bool,
    needs_reboot: bool,
    needs_shutdown: bool,
    needs_activation: bool,
}

fn ordered(mut values: Vec<String>) -> Vec<String> {
    values.sort_unstable();
    values.dedup();
    values
}

impl TryFrom<ObservedDevice> for Device {
    type Error = std::io::Error;

    fn try_from(record: ObservedDevice) -> std::io::Result<Self> {
        let plugin = record
            .plugin
            .filter(|plugin| matches!(plugin.as_str(), "nvme" | "uefi_capsule"))
            .ok_or_else(|| invalid("unexpected plugin in Host firmware inventory"))?;
        let guids = ordered(record.guid);
        let protocols = ordered(record.protocols);
        let vendor_ids = ordered(record.vendor_ids);
        if !lower_hex(&record.device_id, 40)
            || record.name.as_ref().is_some_and(|name| !label(name, 128))
            || record
                .version
                .as_ref()
                .is_some_and(|version| !label(version, 64))
            || guids.len() > 32
            || guids.iter().any(|guid| !uuid(guid))
            || protocols.len() > 8
            || protocols.iter().any(|name| !label(name, 48))
            || vendor_ids.len() > 8
            || vendor_ids.iter().any(|name| !label(name, 64))
        {
            return Err(invalid("invalid or unbounded Host firmware device"));
        }
        Ok(Self {
            device_id: record.device_id,
            plugin,
            name: record.name,
            guids,
            protocols,
            vendor_ids,
            installed_version: record.version,
            installed_version_raw: record.version_raw,
            version_format: record.version_format,
            updatable: has(&record.flags, "updatable"),
            inhibited: !record.problems.is_empty(),
            needs_reboot: has(&record.flags, "needs-reboot"),
            needs_shutdown: has(&record.flags, "needs-shutdown"),
            needs_activation: has(&record.flags, "needs-activation"),
        })
    }
}

pub(crate) fn inventory_page(after: Option<&InventoryCursor>) -> Result<InventoryReply> {
    let (fwupd_version, devices) = live::inventory()?;
    page(fwupd_version, devices, Timestamp::now().as_second(), after)
}

fn page(
    fwupd_version: String,
    observed: Devices,
    checked_at: i64,
    after: Option<&InventoryCursor>,
) -> Result<InventoryReply> {
    if !label(&fwupd_version, 64) {
        return Err(invalid("invalid installed fwupd version").into());
    }
    let mut devices = observed
        .devices
        .into_iter()
        .filter(|device| !has(&device.flags, "emulated") && !has(&device.flags, "historical"))
        .map(Device::try_from)
        .collect::<std::io::Result<Vec<_>>>()?;
    devices.sort_unstable_by(|left, right| left.device_id.cmp(&right.device_id));
    if devices
        .windows(2)
        .any(|pair| pair[0].device_id == pair[1].device_id)
    {
        return Err(invalid("duplicate physical device identity in firmware inventory").into());
    }
    let generation_sha256 = digest(&serde_json::to_vec(&(&fwupd_version, &devices))?);
    let index = match after {
        Some(cursor) if cursor.generation_sha256 != generation_sha256 => {
            return Ok(InventoryReply::Changed);
        }
        Some(cursor) => {
            match devices.binary_search_by(|device| device.device_id.cmp(&cursor.after)) {
                Ok(index) if index + 1 < devices.len() => index + 1,
                _ => return Ok(InventoryReply::InvalidCursor),
            }
        }
        None => 0,
    };
    let more = index + 1 < devices.len();
    let device = devices.into_iter().nth(index);
    let next = device
        .as_ref()
        .filter(|_| more)
        .map(|device| InventoryCursor {
            generation_sha256: generation_sha256.clone(),
            after: device.device_id.clone(),
        });
    Ok(InventoryReply::Page(Box::new(InventoryPage {
        fwupd_version,
        checked_at,
        generation_sha256,
        device,
        next,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nvme(character: &str, version: &str) -> ObservedDevice {
        ObservedDevice {
            device_id: character.repeat(40),
            plugin: Some("nvme".into()),
            name: Some("Shared model".into()),
            serial: Some("sensitive controller serial".into()),
            version: Some(version.into()),
            ..Default::default()
        }
    }

    #[test]
    fn pages_exact_devices_and_rejects_stale_observations() -> Result<()> {
        let first = nvme("a", "1.0");
        let second = nvme("b", "2.0");
        let live = |second| Devices {
            devices: vec![second, first.clone()],
        };
        let InventoryReply::Page(first_page) =
            page("2.1.10".into(), live(second.clone()), 10, None)?
        else {
            panic!("expected first inventory page");
        };
        assert!(!serde_json::to_string(&first_page)?.contains("serial"));
        let cursor = first_page.next.as_ref().unwrap();
        assert_eq!(cursor.after, "a".repeat(40));
        let InventoryReply::Page(second_page) =
            page("2.1.10".into(), live(second.clone()), 11, Some(cursor))?
        else {
            panic!("expected second inventory page");
        };
        assert_eq!(second_page.checked_at, 11);
        assert_eq!(
            second_page.device.unwrap().installed_version.as_deref(),
            Some("2.0")
        );
        assert!(second_page.next.is_none());
        assert!(matches!(
            page("2.1.10".into(), live(nvme("b", "3.0")), 12, Some(cursor))?,
            InventoryReply::Changed
        ));
        assert!(page("2.1.10".into(), live(first.clone()), 13, None).is_err());
        Ok(())
    }
}
