//! Admit a catalog and read the selected physical device from a pinned fwupd peer.

use std::ffi::{CStr, CString};
use std::fs::{self, File};
use std::io::{Seek, Write};
use std::os::fd::AsFd;
use std::path::Path;

use jiff::Timestamp;
use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, memfd_create};

use super::bus::{Bus, Message};
use super::{
    DeviceIdentity, Devices, Esrt, Observation, ObservedDevice, ObservedRelease, Offer, Platform,
    Policy,
};
use crate::{Result, invalid, state};

const ADDRESS: &CStr = c"unix:path=/run/fvca/firmware-bus";
const DAEMON: &str = "/usr/libexec/fwupd/fwupd";
const FWUPD: &CStr = c"org.freedesktop.fwupd";
const DBUS: &CStr = c"org.freedesktop.DBus";
const DBUS_PATH: &CStr = c"/org/freedesktop/DBus";
const PROPERTIES: &CStr = c"org.freedesktop.DBus.Properties";
const DMI: &str = "/sys/class/dmi/id";
const ESRT: &str = "/sys/firmware/efi/esrt/entries";

struct Peer {
    bus: Bus,
    owner: CString,
}

impl Peer {
    fn connect(address: &CStr, expected_uid: u32, executable: &Path) -> Result<Self> {
        let bus = Bus::connect(address)?;
        let mut resolved = bus.call(DBUS, DBUS_PATH, DBUS, c"GetNameOwner", &[FWUPD])?;
        let owner = resolved.string()?;
        resolved.finish()?;
        if !owner.starts_with(':') || owner.len() > 64 {
            return Err(invalid("fwupd did not resolve to a unique D-Bus owner").into());
        }
        let owner = CString::new(owner)?;
        let mut uid = bus.call(DBUS, DBUS_PATH, DBUS, c"GetConnectionUnixUser", &[&owner])?;
        let user = uid.u32()?;
        uid.finish()?;
        let mut process = bus.call(
            DBUS,
            DBUS_PATH,
            DBUS,
            c"GetConnectionUnixProcessID",
            &[&owner],
        )?;
        let pid = process.u32()?;
        process.finish()?;
        if user != expected_uid
            || pid == 0
            || fs::read_link(format!("/proc/{pid}/exe"))? != executable
        {
            return Err(invalid("fwupd D-Bus owner is not the expected daemon process").into());
        }
        Ok(Self { bus, owner })
    }

    fn property<T>(
        &self,
        property: &CStr,
        kind: &CStr,
        parse: impl FnOnce(&mut Message) -> Result<T>,
    ) -> Result<T> {
        let mut reply = self
            .bus
            .call(&self.owner, c"/", PROPERTIES, c"Get", &[FWUPD, property])?;
        let value = reply.variant(kind, parse)?;
        reply.finish()?;
        Ok(value)
    }

    fn version(&self) -> Result<String> {
        if !self.property(c"OnlyTrusted", c"b", Message::boolean)?
            || self.property(c"Tainted", c"b", Message::boolean)?
        {
            return Err(invalid("fwupd is tainted or permits untrusted firmware").into());
        }
        self.property(c"DaemonVersion", c"s", Message::string)
    }

    fn catalog(&self) -> Result<String> {
        self.property(c"FvcaCatalog", c"s", Message::string)
    }

    fn devices(&self) -> Result<Devices> {
        let mut reply = self
            .bus
            .call(&self.owner, c"/", FWUPD, c"GetDevices", &[])?;
        let devices = reply.array(c"a{sv}", device)?;
        reply.finish()?;
        Ok(Devices { devices })
    }

    fn upgrades(&self, device: &str) -> Result<Vec<ObservedRelease>> {
        let exact = CString::new(device)?;
        let mut reply = self
            .bus
            .call(&self.owner, c"/", FWUPD, c"GetUpgrades", &[&exact])?;
        let releases = reply.array(c"a{sv}", release)?;
        reply.finish()?;
        Ok(releases)
    }
}

// Wire bit positions of the fwupd D-Bus ABI, including every flag used by admission.
const DEVICE_FLAGS: &[(u32, &str)] = &[
    (0, "internal"),
    (1, "updatable"),
    (3, "require-ac"),
    (4, "locked"),
    (5, "supported"),
    (6, "needs-bootloader"),
    (8, "needs-reboot"),
    (9, "reported"),
    (10, "notified"),
    (13, "is-bootloader"),
    (14, "wait-for-replug"),
    (17, "needs-shutdown"),
    (18, "another-write-required"),
    (20, "needs-activation"),
    (22, "historical"),
    (24, "will-disappear"),
    (25, "can-verify"),
    (26, "can-verify-image"),
    (27, "dual-image"),
    (28, "self-recovery"),
    (29, "usable-during-update"),
    (30, "version-check-required"),
    (31, "install-all-releases"),
    (37, "updatable-hidden"),
    (39, "has-multiple-branches"),
    (40, "backup-before-install"),
    (42, "wildcard-install"),
    (43, "only-version-upgrade"),
    (44, "unreachable"),
    (45, "affects-fde"),
    (46, "end-of-life"),
    (47, "signed-payload"),
    (48, "unsigned-payload"),
    (49, "emulated"),
    (50, "emulation-tag"),
    (51, "only-explicit-updates"),
    (52, "can-emulation-tag"),
    (53, "install-skip-version-check"),
];

const RELEASE_FLAGS: &[(u32, &str)] = &[
    (0, "trusted-payload"),
    (1, "trusted-metadata"),
    (2, "is-upgrade"),
    (3, "is-downgrade"),
    (4, "blocked-version"),
    (5, "blocked-approval"),
    (6, "is-alternate-branch"),
    (7, "is-community"),
    (8, "trusted-report"),
];

fn flags(bits: u64, known: &[(u32, &str)]) -> Vec<String> {
    let mut names = Vec::new();
    let mut remaining = bits;
    for &(shift, name) in known {
        let bit = 1 << shift;
        if bits & bit != 0 {
            names.push(name.into());
            remaining &= !bit;
        }
    }
    if remaining != 0 {
        names.push("unknown".into());
    }
    names
}

fn string(message: &mut Message) -> Result<String> {
    message.variant(c"s", Message::string)
}

fn split(value: &str, delimiter: char) -> Result<Vec<String>> {
    let entries: Vec<_> = value.split(delimiter).map(str::to_owned).collect();
    if entries.len() > 128 || entries.iter().any(String::is_empty) {
        return Err(invalid("invalid fwupd D-Bus string list").into());
    }
    Ok(entries)
}

fn device(message: &mut Message) -> Result<ObservedDevice> {
    let mut record = ObservedDevice::default();
    message.dictionary(|field, value| {
        match field {
            "DeviceId" => record.device_id = string(value)?,
            "Name" => record.name = Some(string(value)?),
            "Plugin" => record.plugin = Some(string(value)?),
            "Guid" => {
                record.guid = value.variant(c"as", |value| value.array(c"s", Message::string))?
            }
            "Protocol" => record.protocols = split(&string(value)?, '|')?,
            "VendorId" => record.vendor_ids = split(&string(value)?, '|')?,
            "Serial" => record.serial = Some(string(value)?),
            "Version" => record.version = Some(string(value)?),
            "VersionRaw" => record.version_raw = Some(value.variant(c"t", Message::u64)?),
            "VersionFormat" => {
                record.version_format = match value.variant(c"u", Message::u32)? {
                    1 => Some("plain"),
                    2 => Some("number"),
                    3 => Some("pair"),
                    4 => Some("triplet"),
                    5 => Some("quad"),
                    _ => None,
                }
                .map(str::to_owned);
            }
            "Flags" => record.flags = flags(value.variant(c"t", Message::u64)?, DEVICE_FLAGS),
            "Problems" => {
                if value.variant(c"t", Message::u64)? != 0 {
                    record.problems.push("inhibited".into());
                }
            }
            _ => value.skip_variant()?,
        }
        Ok(())
    })?;
    if record.device_id.is_empty() {
        return Err(invalid("fwupd D-Bus device is missing its ID").into());
    }
    Ok(record)
}

fn release(message: &mut Message) -> Result<ObservedRelease> {
    let mut record = ObservedRelease::default();
    message.dictionary(|field, value| {
        match field {
            "Version" => record.version = Some(string(value)?),
            "RemoteId" => record.remote_id = Some(string(value)?),
            "Protocol" => record.protocol = Some(string(value)?),
            "Checksum" => record.checksum = split(&string(value)?, ',')?,
            "TrustFlags" => record.flags = flags(value.variant(c"t", Message::u64)?, RELEASE_FLAGS),
            _ => value.skip_variant()?,
        }
        Ok(())
    })?;
    Ok(record)
}

fn attribute(path: &Path, name: &str) -> Result<String> {
    let bytes = state::read(&path.join(name), 4096)?;
    Ok(std::str::from_utf8(&bytes)?.trim_end_matches('\n').into())
}

fn platform(dmi: &Path) -> Result<Platform> {
    Ok(Platform {
        system_uuid: attribute(dmi, "product_uuid")?.to_ascii_lowercase(),
        vendor: attribute(dmi, "sys_vendor")?,
        product: attribute(dmi, "product_name")?,
        board: attribute(dmi, "board_name")?,
        board_revision: attribute(dmi, "board_version")?,
    })
}

fn esrt(path: &Path) -> Result<Vec<Esrt>> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() || entries.len() == 128 {
            return Err(invalid("invalid or excessive ESRT entries").into());
        }
        let path = entry.path();
        entries.push(Esrt {
            guid: attribute(&path, "fw_class")?.to_ascii_lowercase(),
            fw_type: attribute(&path, "fw_type")?.parse()?,
            fw_version: attribute(&path, "fw_version")?.parse()?,
        });
    }
    Ok(entries)
}

fn sealed(name: &CStr, bytes: &[u8]) -> Result<File> {
    let mut file = File::from(memfd_create(
        name,
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING | MemfdFlags::NOEXEC_SEAL,
    )?);
    file.write_all(bytes)?;
    fcntl_add_seals(
        &file,
        SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL,
    )?;
    file.rewind()?;
    Ok(file)
}

fn matches_catalog(receipt: &str, expected: &str) -> bool {
    receipt
        .split_once(':')
        .is_some_and(|(generation, identity)| {
            generation.parse::<u64>().is_ok_and(|number| number != 0) && identity == expected
        })
}

pub(super) struct Session {
    peer: Peer,
    catalog: String,
}

impl Session {
    pub(super) fn open(policy: &Policy, offer: &Offer, payloads: &[Vec<u8>; 2]) -> Result<Self> {
        if offer.remote != "lvfs" || platform(Path::new(DMI))? != policy.platform {
            return Err(
                invalid("live catalog import requires the enrolled Host and LVFS remote").into(),
            );
        }
        let peer = Peer::connect(ADDRESS, 0, Path::new(DAEMON))?;
        if peer.version()? != policy.fwupd_version {
            return Err(
                invalid("live fwupd version differs from the signed firmware policy").into(),
            );
        }
        Self::import(peer, &offer.catalog.identity(), payloads)
    }

    fn import(peer: Peer, expected: &str, payloads: &[Vec<u8>; 2]) -> Result<Self> {
        let mut catalog = peer.catalog()?;
        if !matches_catalog(&catalog, expected) {
            let metadata = sealed(c"fvca-lvfs-metadata", &payloads[0])?;
            let signature = sealed(c"fvca-lvfs-signature", &payloads[1])?;
            peer.bus
                .import_lvfs(&peer.owner, metadata.as_fd(), signature.as_fd())?;
            catalog = peer.catalog()?;
            if !matches_catalog(&catalog, expected) {
                return Err(
                    invalid("fwupd did not admit the exact signed firmware catalog").into(),
                );
            }
        }
        Ok(Self { peer, catalog })
    }

    fn require_catalog(&self) -> Result<()> {
        if self.peer.catalog()? != self.catalog {
            return Err(invalid("fwupd firmware catalog changed during intake").into());
        }
        Ok(())
    }

    pub(super) fn read(&self, identity: &DeviceIdentity) -> Result<Observation> {
        self.require_catalog()?;
        let observed = snapshot(
            &self.peer,
            &identity.device_id,
            Path::new(DMI),
            identity.component.esrt_type().map(|_| Path::new(ESRT)),
        )?;
        self.require_catalog()?;
        Ok(observed)
    }
}

fn snapshot(peer: &Peer, id: &str, dmi: &Path, esrt_path: Option<&Path>) -> Result<Observation> {
    let start = Timestamp::now().as_second();
    let platform = platform(dmi)?;
    let fwupd_version = peer.version()?;
    let devices = peer.devices()?;
    let selected = super::unique_device(&devices, id)?;
    let mut upgraded = selected.clone();
    upgraded.releases = peer.upgrades(id)?;
    Ok(Observation {
        schema: "fvca-firmware-observation-v1".into(),
        observed_at: start,
        platform,
        fwupd_version,
        devices,
        upgrades: Devices {
            devices: vec![upgraded],
        },
        esrt: esrt_path.map(esrt).transpose()?.unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "run with tests/check-fwupd-live.py to provide the private bus"]
    fn reads_only_the_pinned_fwupd_peer() -> Result<()> {
        let address = CString::new(std::env::var("FVCA_TEST_FWUPD_ADDRESS")?)?;
        let executable = std::env::var_os("FVCA_TEST_FWUPD_EXECUTABLE").unwrap();
        let mode = std::env::var_os("FVCA_TEST_FWUPD_MODE").unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let error = Peer::connect(&address, uid, Path::new("/unexpected"))
            .err()
            .unwrap();
        assert!(error.to_string().contains("expected daemon process"));
        let error = Peer::connect(&address, uid ^ 1, Path::new(&executable))
            .err()
            .unwrap();
        assert!(error.to_string().contains("expected daemon process"));
        let peer = Peer::connect(&address, uid, Path::new(&executable))?;

        let directory = tempfile::tempdir()?;
        let esrt = directory.path().join("esrt");
        let entry = esrt.join("entry0");
        fs::create_dir_all(&entry)?;
        let guid = "a1234567-d234-4031-a111-000000000000";
        for (file, value) in [
            ("product_uuid", "D0290B27-4076-4122-9600-A3BB1936AC38\n"),
            ("sys_vendor", "Fixture Vendor\n"),
            ("product_name", "Fixture Product\n"),
            ("board_name", "Fixture Board\n"),
            ("board_version", "A\n"),
        ] {
            fs::write(directory.path().join(file), value)?;
        }
        fs::write(entry.join("fw_class"), guid.to_ascii_uppercase())?;
        fs::write(entry.join("fw_type"), "1\n")?;
        fs::write(entry.join("fw_version"), "65578\n")?;

        let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let read = || snapshot(&peer, id, directory.path(), Some(&esrt));
        let observed = read()?;
        assert_eq!(
            observed.platform.system_uuid,
            "d0290b27-4076-4122-9600-a3bb1936ac38"
        );
        assert_eq!(observed.platform.board, "Fixture Board");
        assert_eq!(observed.fwupd_version, "2.0.20");
        assert_eq!(observed.esrt[0].guid, guid);
        assert_eq!(observed.esrt[0].fw_type, 1);
        assert_eq!(observed.esrt[0].fw_version, 65578);
        let device = super::super::unique_device(&observed.upgrades, id)?;
        assert_eq!(device.version_format.as_deref(), Some("pair"));
        assert_eq!(device.version_raw, Some(65578));
        assert_eq!(device.flags, ["internal", "updatable", "needs-reboot"]);
        assert_eq!(device.vendor_ids, ["DMI:Fixture", "UEFI:Fixture"]);
        let release = &device.releases[0];
        assert_eq!(release.remote_id.as_deref(), Some("lvfs"));
        assert_eq!(release.checksum[1], "7".repeat(64));
        assert_eq!(
            release.flags,
            ["trusted-metadata", "is-upgrade", "trusted-report"]
        );

        for (setting, reason) in [
            ("untrusted", "tainted or permits untrusted firmware"),
            ("tainted", "tainted or permits untrusted firmware"),
            ("duplicate", "observation is ambiguous"),
            ("oversized", "string exceeds its size bound"),
        ] {
            fs::write(&mode, setting)?;
            let error = read().err().unwrap();
            assert!(error.to_string().contains(reason), "{setting}: {error}");
        }
        fs::write(&mode, "wrong-type")?;
        let error = read().err().unwrap();
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .raw_os_error(),
            Some(rustix::io::Errno::NXIO.raw_os_error())
        );

        fs::write(&mode, "normal")?;
        let payloads = [b"exact catalog".to_vec(), b"exact JCat".to_vec()];
        let identity = format!(
            "{}:{}",
            crate::channel::digest(&payloads[0]),
            crate::channel::digest(&payloads[1]),
        );
        let session = Session::import(peer, &identity, &payloads)?;
        session.require_catalog()?;
        fs::write(&mode, "catalog-replaced")?;
        let error = session.require_catalog().err().unwrap();
        assert!(error.to_string().contains("catalog changed during intake"));
        Ok(())
    }
}
