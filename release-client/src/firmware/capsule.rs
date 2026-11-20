//! Observe the on-disk capsule route without opening a disk or writing EFI state.

use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use fvca_trial_authorization::efi;
use rustix::fs::{self, CWD, Dir, Mode, OFlags, ResolveFlags, StatFs, StatVfsMountFlags};
use rustix::io::Errno;
use serde::Serialize;

use super::{Esrt, boot_id};
use crate::{Result, channel::digest, handoff, invalid, state};

const EFIVARS: &str = "/sys/firmware/efi/efivars";
const EFIVARFS_MAGIC: u64 = 0xde5e81e4;
const VFAT_MAGIC: u64 = 0x4d44;
const ESP_PATH_LIMIT: usize = 256;
const WITHIN_MOUNT: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_XDEV);
const X86_EFIVAR_RESERVE: u64 = 5 * 1024;
// Allow two 128-byte records for setting and restoring OsIndications. Each
// includes the eight-byte value, UTF-16 name and room for headers and padding.
const EFIVAR_REQUIRED: u64 = 2 * 128;
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
        efivar_available_bytes: u64,
        efivar_required_bytes: u64,
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
    let efivars = File::from(fs::openat(CWD, EFIVARS, DIRECTORY, Mode::empty())?);
    let efivar_available = efivar_space(&fs::fstatfs(&efivars)?)?;
    let boot_id = boot_id()?;
    let boot_entry = route(&efivars, expected, esrt, target)?;
    let required = required_space(payload_bytes)?;
    let available = esp_space(Path::new(efi::FIRMWARE_ESP), device_id)?;
    if available < required {
        return Err(invalid(&format!(
            "firmware ESP has {available} available bytes and requires {required}"
        ))
        .into());
    }
    Ok((
        boot_id,
        Route::Matched {
            boot_entry,
            esp_device_path_sha256: digest(expected),
            esp_available_bytes: available,
            esp_required_bytes: required,
            efivar_available_bytes: efivar_available,
            efivar_required_bytes: EFIVAR_REQUIRED,
        },
    ))
}

fn efivar_space(space: &StatFs) -> io::Result<u64> {
    if space.f_type as u64 != EFIVARFS_MAGIC {
        return Err(invalid(
            "capsule routing requires the kernel efivarfs mount",
        ));
    }
    // Linux reports QueryVariableInfo for nonvolatile runtime variables in
    // one-byte blocks, or a zero store size when it cannot query firmware.
    if space.f_bsize != 1
        || space.f_frsize != 1
        || space.f_blocks == 0
        || space.f_bavail > space.f_bfree
        || space.f_bfree > space.f_blocks
    {
        return Err(invalid(
            "firmware EFI variable capacity is unavailable or invalid",
        ));
    }
    if space.f_bavail > space.f_bfree.saturating_sub(X86_EFIVAR_RESERVE) {
        return Err(invalid("the kernel EFI variable store reserve is missing"));
    }
    if space.f_bavail < EFIVAR_REQUIRED {
        return Err(invalid(&format!(
            "firmware EFI variable store has {} available bytes and requires {EFIVAR_REQUIRED}",
            space.f_bavail,
        )));
    }
    Ok(space.f_bavail)
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
    let efi = fs::openat2(root, "EFI", DIRECTORY, Mode::empty(), WITHIN_MOUNT)?;
    let queue = match fs::openat2(
        &efi,
        "UpdateCapsule",
        DIRECTORY,
        Mode::empty(),
        WITHIN_MOUNT,
    ) {
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

fn read(variables: &File, name: &str) -> io::Result<Vec<u8>> {
    let fetch = || -> io::Result<_> {
        let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOCTTY;
        let file = File::from(fs::openat2(
            variables,
            format!("{name}-{}", efi::GLOBAL).as_str(),
            flags,
            Mode::empty(),
            WITHIN_MOUNT,
        )?);
        if !file.metadata()?.is_file() {
            return Err(invalid("expected a regular EFI variable file"));
        }
        let mut raw = Vec::new();
        file.take(4097).read_to_end(&mut raw)?;
        if raw.is_empty() || raw.len() > 4096 {
            return Err(invalid("EFI variable exceeds its size bound or is empty"));
        }
        Ok(raw)
    };
    fetch().map_err(|error| io::Error::new(error.kind(), format!("EFI {name}: {error}")))
}

fn mask(raw: &[u8], attributes: u32) -> io::Result<u64> {
    let bytes = efi::variable_data(raw, attributes)?
        .try_into()
        .map_err(|_| invalid("malformed EFI indication mask"))?;
    Ok(u64::from_le_bytes(bytes))
}

fn route(variables: &File, expected: &[u8], esrt: &Esrt, target: u32) -> Result<u16> {
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
    fn requires_efivarfs_capacity_above_the_kernel_reserve() -> Result<()> {
        let work = tempfile::tempdir()?;
        let mut stats = rustix::fs::fstatfs(File::open(work.path())?)?;
        assert!(efivar_space(&stats).is_err());
        stats.f_type = EFIVARFS_MAGIC as _;
        stats.f_bsize = 1;
        stats.f_frsize = 1;
        stats.f_blocks = 196_608;
        stats.f_bfree = 26_002;
        stats.f_bavail = 20_882;
        assert_eq!(efivar_space(&stats)?, 20_882);
        stats.f_bfree = stats.f_blocks + 1;
        assert!(efivar_space(&stats).is_err());
        stats.f_bfree = X86_EFIVAR_RESERVE + EFIVAR_REQUIRED;
        stats.f_bavail = EFIVAR_REQUIRED;
        assert_eq!(efivar_space(&stats)?, EFIVAR_REQUIRED);
        stats.f_bavail -= 1;
        assert!(
            efivar_space(&stats)
                .unwrap_err()
                .to_string()
                .contains("available bytes")
        );
        stats.f_bavail = stats.f_bfree;
        assert!(
            efivar_space(&stats)
                .unwrap_err()
                .to_string()
                .contains("reserve is missing")
        );
        stats.f_bfree = 0;
        stats.f_bavail = 0;
        stats.f_blocks = 0;
        assert!(
            efivar_space(&stats)
                .unwrap_err()
                .to_string()
                .contains("unavailable")
        );
        Ok(())
    }

    #[test]
    fn matches_only_the_running_signed_esp_and_an_idle_firmware_route() -> Result<()> {
        let work = tempfile::tempdir()?;
        let dir = work.path();
        let efivars = File::open(dir)?;
        let expected = efi::esp_device_path(ESP, 1, 256, 64_000)?;
        assert_eq!(
            &expected[24..42],
            &hex::decode("1edb9549221144335566778899aabbcc0202")?
        );
        let esrt = baseline();
        let require = || route(&efivars, &expected, &esrt, TARGET);
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
        let unrelated = dir.join("unrelated");
        fs::write(&unrelated, [BOOT_RUNTIME as u8, 0, 0, 0, 1])?;
        fs::remove_file(dir.join(format!("SecureBoot-{}", efi::GLOBAL)))?;
        std::os::unix::fs::symlink(unrelated, dir.join(format!("SecureBoot-{}", efi::GLOBAL)))?;
        assert!(require().is_err());
        Ok(())
    }

    #[test]
    fn refuses_a_capsule_below_the_esrt_floor_or_with_an_existing_attempt() -> Result<()> {
        let work = tempfile::tempdir()?;
        let dir = work.path();
        let efivars = File::open(dir)?;
        let expected = efi::esp_device_path(ESP, 1, 256, 64_000)?;
        variables(dir, &expected)?;
        let mut esrt = baseline();
        esrt.lowest_supported_fw_version = TARGET + 1;
        assert!(
            route(&efivars, &expected, &esrt, TARGET)
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
                route(&efivars, &expected, &esrt, TARGET)
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("already records an attempt")
            );
        }
        Ok(())
    }
}
