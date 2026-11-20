//! Observe the on-disk capsule route without opening a disk or writing EFI state.

use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use fvca_trial_authorization::efi;
use rustix::fs::{self, CWD, Dir, Mode, OFlags, ResolveFlags, StatVfsMountFlags};
use rustix::io::Errno;
use serde::Serialize;

use super::{Esrt, uuid};
use crate::{Result, channel::digest, handoff, invalid, state};

const EFIVARS: &str = "/sys/firmware/efi/efivars";
const BOOT_ID: &str = "/proc/sys/kernel/random/boot_id";
const EFIVARFS_MAGIC: u64 = 0xde5e81e4;
const VFAT_MAGIC: u64 = 0x4d44;
const ESP_PATH_LIMIT: usize = 256;
const DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const BOOT_RUNTIME: u32 = 6;
const NON_VOLATILE: u32 = 7;
const FILE_CAPSULE: u64 = 0x4;

#[derive(Serialize)]
pub(super) struct Delivery {
    esrt: Esrt,
    #[serde(skip_serializing_if = "Option::is_none")]
    boot_id: Option<String>,
    #[serde(flatten)]
    route: Route,
}

#[derive(Serialize)]
#[serde(tag = "disposition", rename_all = "kebab-case")]
enum Route {
    Matched {
        boot_entry: u16,
        esp_device_path_sha256: String,
        esp_available_bytes: u64,
        esp_required_bytes: u64,
    },
    Blocked {
        reason: String,
    },
}

pub(super) fn inspect(esrt: Esrt, target: u32, payload_bytes: u64) -> Delivery {
    let (boot_id, route) = match live_route(&esrt, target, payload_bytes) {
        Ok((boot_id, route)) => (Some(boot_id), route),
        Err(error) => (
            None,
            Route::Blocked {
                reason: error.to_string(),
            },
        ),
    };
    Delivery {
        esrt,
        boot_id,
        route,
    }
}

fn live_route(esrt: &Esrt, target: u32, payload_bytes: u64) -> Result<(String, Route)> {
    let _lease = handoff::lock_install()?;
    handoff::require_idle()?;
    let path = Path::new(efi::FIRMWARE_ESP_BINDING);
    let file = state::open_regular(path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("verified firmware ESP binding: {error}"),
        )
    })?;
    handoff::private_file(&file)?;
    let mut binding = Vec::new();
    file.take((ESP_PATH_LIMIT + size_of::<u64>() + 1) as u64)
        .read_to_end(&mut binding)?;
    let (device_id, expected) = esp_binding(&binding)?;
    let efivars = Path::new(EFIVARS);
    if rustix::fs::fstatfs(File::open(efivars)?)?.f_type as u64 != EFIVARFS_MAGIC {
        return Err(invalid("capsule routing requires the kernel efivarfs mount").into());
    }
    let boot = state::read(Path::new(BOOT_ID), 37)?;
    let boot_id = std::str::from_utf8(&boot)?
        .strip_suffix('\n')
        .filter(|id| uuid(id))
        .ok_or_else(|| invalid("invalid Linux boot identifier"))?;
    let boot_entry = route(efivars, expected, esrt, target)?;
    let required = required_space(payload_bytes)?;
    let available = esp_space(Path::new(efi::FIRMWARE_ESP), device_id)?;
    if available < required {
        return Err(invalid(&format!(
            "firmware ESP has {available} available bytes and requires {required}"
        ))
        .into());
    }
    Ok((
        boot_id.to_owned(),
        Route::Matched {
            boot_entry,
            esp_device_path_sha256: digest(expected),
            esp_available_bytes: available,
            esp_required_bytes: required,
        },
    ))
}

fn esp_binding(binding: &[u8]) -> io::Result<(u64, &[u8])> {
    let (device, path) = binding
        .split_first_chunk::<8>()
        .ok_or_else(|| invalid("truncated verified firmware ESP binding"))?;
    let device_id = u64::from_le_bytes(*device);
    if device_id == 0 || !(1..=ESP_PATH_LIMIT).contains(&path.len()) {
        return Err(invalid("invalid verified firmware ESP binding"));
    }
    Ok((device_id, path))
}

fn required_space(payload_bytes: u64) -> io::Result<u64> {
    // Match fwupd's default backup allowance. The extra MiB also covers
    // filesystem allocation overhead and a capsule header added by fwupd.
    payload_bytes
        .checked_mul(2)
        .and_then(|size| size.checked_add(1024 * 1024))
        .filter(|_| payload_bytes != 0)
        .ok_or_else(|| invalid("invalid firmware payload size for ESP reservation"))
}

fn esp_space(path: &Path, device_id: u64) -> io::Result<u64> {
    let root = File::from(fs::openat(CWD, path, DIRECTORY, Mode::empty())?);
    let flags = StatVfsMountFlags::RDONLY
        | StatVfsMountFlags::NODEV
        | StatVfsMountFlags::NOSUID
        | StatVfsMountFlags::NOEXEC;
    let space = fs::fstatvfs(&root)?;
    if root.metadata()?.dev() != device_id
        || fs::fstatfs(&root)?.f_type as u64 != VFAT_MAGIC
        || !space.f_flag.contains(flags)
    {
        return Err(invalid(
            "firmware ESP is not the verified read-only VFAT mount",
        ));
    }
    require_empty_capsule_directory(&root)?;
    space
        .f_bavail
        .checked_mul(space.f_frsize)
        .filter(|_| space.f_frsize != 0)
        .ok_or_else(|| invalid("invalid firmware ESP space accounting"))
}

fn require_empty_capsule_directory(root: &File) -> io::Result<()> {
    let resolve = ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV;
    let efi = fs::openat2(root, "EFI", DIRECTORY, Mode::empty(), resolve)?;
    let queue = match fs::openat2(&efi, "UpdateCapsule", DIRECTORY, Mode::empty(), resolve) {
        Ok(queue) => queue,
        Err(Errno::NOENT) => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    for entry in Dir::new(queue)? {
        if !matches!(entry?.file_name().to_bytes(), b"." | b"..") {
            return Err(invalid(
                "firmware ESP already contains a queued capsule or foreign entry",
            ));
        }
    }
    Ok(())
}

fn read(variables: &Path, name: &str) -> io::Result<Vec<u8>> {
    state::read(&variables.join(format!("{name}-{}", efi::GLOBAL)), 4096)
        .map_err(|error| io::Error::new(error.kind(), format!("EFI {name}: {error}")))
}

fn mask(raw: &[u8], attributes: u32) -> io::Result<u64> {
    let bytes = efi::variable_data(raw, attributes)?
        .try_into()
        .map_err(|_| invalid("malformed EFI indication mask"))?;
    Ok(u64::from_le_bytes(bytes))
}

fn route(variables: &Path, expected: &[u8], esrt: &Esrt, target: u32) -> Result<u16> {
    if target < esrt.lowest_supported_fw_version {
        return Err(invalid("capsule target is below the device's ESRT firmware floor").into());
    }
    if esrt.last_attempt_version == target {
        return Err(invalid("ESRT already records an attempt at this capsule target").into());
    }
    if efi::variable_data(&read(variables, "SecureBoot")?, BOOT_RUNTIME)? != [1]
        || efi::variable_data(&read(variables, "SetupMode")?, BOOT_RUNTIME)? != [0]
    {
        return Err(
            invalid("capsule routing requires enabled Secure Boot outside Setup Mode").into(),
        );
    }
    if mask(&read(variables, "OsIndicationsSupported")?, BOOT_RUNTIME)? & FILE_CAPSULE == 0 {
        return Err(invalid("firmware does not advertise capsule-on-disk delivery").into());
    }
    match read(variables, "OsIndications") {
        Ok(raw) if mask(&raw, NON_VOLATILE)? == 0 => (),
        Ok(_) => return Err(invalid("another EFI indication is pending").into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    match read(variables, "BootNext") {
        Ok(_) => return Err(invalid("a one-shot EFI boot override is pending").into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    let current = read(variables, "BootCurrent")?;
    let current = u16::from_le_bytes(
        efi::variable_data(&current, BOOT_RUNTIME)?
            .try_into()
            .map_err(|_| invalid("malformed EFI BootCurrent"))?,
    );
    let order = read(variables, "BootOrder")?;
    if efi::boot_order(efi::variable_data(&order, NON_VOLATILE)?)?.first() != Some(&current) {
        return Err(invalid("the running EFI boot entry is not first in BootOrder").into());
    }
    let option = read(variables, &format!("Boot{current:04X}"))?;
    efi::require_esp_load_option(efi::variable_data(&option, NON_VOLATILE)?, expected)?;
    Ok(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const ESP: &str = "4995db1e-1122-3344-5566-778899aabbcc";
    const TARGET: u32 = 65587;

    fn put(dir: &Path, name: &str, attributes: u32, data: &[u8]) -> io::Result<()> {
        let mut raw = attributes.to_le_bytes().to_vec();
        raw.extend_from_slice(data);
        fs::write(dir.join(format!("{name}-{}", efi::GLOBAL)), raw)
    }

    fn option(device_path: &[u8]) -> Vec<u8> {
        let mut raw = 1u32.to_le_bytes().to_vec();
        raw.extend_from_slice(&(device_path.len() as u16).to_le_bytes());
        raw.extend_from_slice(&[b'A', 0, 0, 0]);
        raw.extend_from_slice(device_path);
        raw
    }

    fn baseline() -> Esrt {
        Esrt {
            guid: "ed151d94-9d52-4a39-b0aa-c0088fdcaa4f".into(),
            fw_type: 1,
            fw_version: 65578,
            lowest_supported_fw_version: 65578,
            capsule_flags: 0x50000,
            last_attempt_version: 65578,
            last_attempt_status: 0,
        }
    }

    fn variables(dir: &Path, expected: &[u8]) -> io::Result<()> {
        for (name, value) in [
            ("SecureBoot", &[1][..]),
            ("SetupMode", &[0][..]),
            ("BootCurrent", &[2, 0][..]),
            ("OsIndicationsSupported", &0x1fu64.to_le_bytes()[..]),
        ] {
            put(dir, name, BOOT_RUNTIME, value)?;
        }
        put(dir, "BootOrder", NON_VOLATILE, &[2, 0, 3, 0])?;
        put(dir, "Boot0002", NON_VOLATILE, &option(expected))
    }

    #[test]
    fn bounds_space_and_requires_the_selected_read_only_vfat() -> Result<()> {
        let work = tempfile::tempdir()?;
        let expected = efi::esp_device_path(ESP, 1, 256, 64_000)?;
        let device = 0x801u64;
        let mut binding = device.to_le_bytes().to_vec();
        binding.extend_from_slice(&expected);
        assert_eq!(esp_binding(&binding)?, (device, expected.as_slice()));
        assert!(esp_binding(&binding[..8]).is_err());
        binding[..8].fill(0);
        assert!(esp_binding(&binding).is_err());
        assert_eq!(required_space(16_908_288)?, 34_865_152);
        assert!(required_space(0).is_err());
        assert!(required_space(u64::MAX).is_err());
        let device = fs::metadata(work.path())?.dev();
        assert!(
            esp_space(work.path(), device)
                .unwrap_err()
                .to_string()
                .contains("read-only VFAT")
        );
        Ok(())
    }

    #[test]
    fn accepts_only_an_empty_or_absent_capsule_directory() -> Result<()> {
        let work = tempfile::tempdir()?;
        let root = File::open(work.path())?;
        let efi = work.path().join("EFI");
        let queue = efi.join("UpdateCapsule");
        assert!(require_empty_capsule_directory(&root).is_err());
        fs::create_dir(&efi)?;
        require_empty_capsule_directory(&root)?;
        fs::create_dir(&queue)?;
        require_empty_capsule_directory(&root)?;
        let foreign = queue.join(".unknown");
        fs::write(&foreign, b"foreign capsule")?;
        assert!(
            require_empty_capsule_directory(&root)
                .unwrap_err()
                .to_string()
                .contains("queued capsule or foreign entry")
        );
        fs::remove_file(foreign)?;
        fs::remove_dir(&queue)?;
        std::os::unix::fs::symlink(work.path(), &queue)?;
        assert!(require_empty_capsule_directory(&root).is_err());
        Ok(())
    }

    #[test]
    fn matches_only_the_running_signed_esp_and_an_idle_firmware_route() -> Result<()> {
        let work = tempfile::tempdir()?;
        let dir = work.path();
        let expected = efi::esp_device_path(ESP, 1, 256, 64_000)?;
        assert_eq!(
            &expected[24..42],
            &hex::decode("1edb9549221144335566778899aabbcc0202")?
        );
        let esrt = baseline();
        let require = || route(dir, &expected, &esrt, TARGET);
        variables(dir, &expected)?;
        assert_eq!(require()?, 2);
        for (name, attributes, contents, reason) in [
            ("SecureBoot", BOOT_RUNTIME, vec![0], "enabled Secure Boot"),
            ("SetupMode", BOOT_RUNTIME, vec![1], "outside Setup Mode"),
            (
                "OsIndicationsSupported",
                BOOT_RUNTIME,
                0x18u64.to_le_bytes().to_vec(),
                "does not advertise",
            ),
            (
                "OsIndicationsSupported",
                NON_VOLATILE,
                4u64.to_le_bytes().to_vec(),
                "unexpected EFI variable attributes",
            ),
            (
                "OsIndicationsSupported",
                BOOT_RUNTIME,
                vec![4],
                "malformed EFI indication mask",
            ),
            (
                "BootOrder",
                NON_VOLATILE,
                vec![3, 0, 2, 0],
                "not first in BootOrder",
            ),
            (
                "BootOrder",
                NON_VOLATILE,
                vec![2, 0, 2, 0],
                "malformed EFI BootOrder",
            ),
            (
                "BootNext",
                NON_VOLATILE,
                vec![2, 0],
                "one-shot EFI boot override",
            ),
            (
                "OsIndications",
                NON_VOLATILE,
                4u64.to_le_bytes().to_vec(),
                "EFI indication is pending",
            ),
            (
                "Boot0002",
                NON_VOLATILE,
                option(&efi::esp_device_path(ESP, 1, 512, 64_000)?),
                "does not match the authorized ESP",
            ),
        ] {
            variables(dir, &expected)?;
            put(dir, name, attributes, &contents)?;
            assert!(
                require().err().unwrap().to_string().contains(reason),
                "{name}"
            );
            fs::remove_file(dir.join(format!("{name}-{}", efi::GLOBAL)))?;
        }
        Ok(())
    }

    #[test]
    fn refuses_a_capsule_below_the_esrt_floor_or_with_an_existing_attempt() -> Result<()> {
        let work = tempfile::tempdir()?;
        let dir = work.path();
        let expected = efi::esp_device_path(ESP, 1, 256, 64_000)?;
        variables(dir, &expected)?;
        let mut esrt = baseline();
        esrt.lowest_supported_fw_version = TARGET + 1;
        assert!(
            route(dir, &expected, &esrt, TARGET)
                .err()
                .unwrap()
                .to_string()
                .contains("firmware floor")
        );
        esrt.lowest_supported_fw_version = esrt.fw_version;
        esrt.last_attempt_version = TARGET;
        for status in [0, 1, 5] {
            esrt.last_attempt_status = status;
            assert!(
                route(dir, &expected, &esrt, TARGET)
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("already records an attempt")
            );
        }
        Ok(())
    }
}
