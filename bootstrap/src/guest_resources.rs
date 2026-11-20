//! Host-owned resource settings for the registered Service Guest.

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use crate::{guest_boot, invalid};

const SIGNED: &str = "/usr/lib/fvca/guest-vm-settings";
const ACTIVE: &str = "/run/fvca/guest-vm-settings";
const RUNTIME_SUPPORT: &str = "/sysroot/usr/lib/fvca/guest-vm-settings-v1";
const LIMIT: usize = 128;
const O_NOFOLLOW: i32 = 0o400000;
const O_NONBLOCK: i32 = 0o4000;
#[cfg(any(feature = "libvirt", test))]
const HOST_RESERVE_MIB: u32 = 1024;
#[cfg(any(feature = "libvirt", test))]
const QEMU_RESERVE_MIB: u32 = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Resources {
    pub vcpus: u32,
    pub memory_mib: u32,
}

impl Resources {
    const PROFILE_DEFAULT: Self = Self {
        vcpus: 2,
        memory_mib: 2048,
    };

    fn parse(data: &str) -> io::Result<Self> {
        let fields: Vec<_> = data.split('\n').collect();
        let ["FVCA-SERVICE-GUEST-VM-1", guest, vcpus, memory, ""] = fields.as_slice() else {
            return Err(invalid("invalid signed Service Guest resource settings"));
        };
        if guest.strip_prefix("guest=").map(str::as_bytes)
            != Some(guest_boot::SERVICE_GUEST_UUID.to_bytes())
        {
            return Err(invalid(
                "resource settings belong to a different Service Guest",
            ));
        }
        let vcpus = decimal(vcpus, "vcpus=")?;
        let memory_mib = decimal(memory, "memory_mib=")?;
        if !(1..=4).contains(&vcpus)
            || !(1024..=4096).contains(&memory_mib)
            || !memory_mib.is_multiple_of(256)
        {
            return Err(invalid(
                "Service Guest resources exceed the approved machine profile",
            ));
        }
        Ok(Self { vcpus, memory_mib })
    }

    pub fn active() -> io::Result<Self> {
        Ok(read(Path::new(ACTIVE), 0o600)?
            .map_or(Self::PROFILE_DEFAULT, |(resources, _)| resources))
    }

    #[cfg(feature = "libvirt")]
    pub fn require_capacity(&self) -> io::Result<()> {
        let cpus = std::thread::available_parallelism()?.get();
        let memory = fs::read_to_string("/proc/meminfo")?;
        self.check_capacity(cpus, &memory)
    }

    #[cfg(any(feature = "libvirt", test))]
    fn check_capacity(&self, cpus: usize, memory: &str) -> io::Result<()> {
        let available = memory
            .lines()
            .find_map(|line| line.strip_prefix("MemAvailable:"))
            .and_then(|value| value.trim_ascii().strip_suffix(" kB"))
            .map(str::trim_ascii)
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| invalid("Host memory headroom is unavailable"))?;
        let required_kib = u64::from(self.memory_mib + HOST_RESERVE_MIB + QEMU_RESERVE_MIB) * 1024;
        if cpus < self.vcpus as usize || available < required_kib {
            return Err(invalid(
                "insufficient Host CPU or memory headroom for the Service Guest",
            ));
        }
        Ok(())
    }
}

fn decimal(line: &str, prefix: &str) -> io::Result<u32> {
    line.strip_prefix(prefix)
        .filter(|value| !value.starts_with('0') && value.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| invalid("invalid Service Guest resource value"))
}

fn read(path: &Path, mode: u32) -> io::Result<Option<(Resources, String)>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != mode
    {
        return Err(invalid("invalid Service Guest resource record file"));
    }
    let mut payload = String::new();
    file.take((LIMIT + 1) as u64).read_to_string(&mut payload)?;
    if payload.len() > LIMIT {
        return Err(invalid(
            "Service Guest resource record exceeds its size bound",
        ));
    }
    Ok(Some((Resources::parse(&payload)?, payload)))
}

pub(crate) fn publish() -> io::Result<()> {
    if let Some((_, payload)) = read(Path::new(SIGNED), 0o644)? {
        if !fs::symlink_metadata(RUNTIME_SUPPORT)
            .is_ok_and(|marker| marker.is_file() && marker.len() == 0)
        {
            return Err(invalid(
                "the verified Hypervisor runtime lacks Guest resource settings support",
            ));
        }
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(ACTIVE)?
            .write_all(payload.as_bytes())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_identity_resource_bounds_and_host_reserves() -> io::Result<()> {
        let record = concat!(
            "FVCA-SERVICE-GUEST-VM-1\n",
            "guest=e629aa43-af11-47c6-aedc-a2dc47f1cc3a\n",
            "vcpus=3\nmemory_mib=2560\n",
        );
        let selected = Resources::parse(record)?;
        assert_eq!(selected.vcpus, 3);
        assert_eq!(selected.memory_mib, 2560);
        for (value, replacement) in [
            ("e629aa43", "00000000"),
            ("vcpus=3", "vcpus=5"),
            ("vcpus=3", "vcpus=03"),
            ("memory_mib=2560", "memory_mib=2561"),
            ("memory_mib=2560", "memory_mib=768"),
            ("memory_mib=2560", "memory_mib=4352"),
            ("memory_mib=2560", "memory_mib=2048\nnetwork=bridge"),
        ] {
            assert!(Resources::parse(&record.replace(value, replacement)).is_err());
        }
        let exact = "MemAvailable:      4194304 kB\n";
        selected.check_capacity(3, exact)?;
        assert!(selected.check_capacity(2, exact).is_err());
        assert!(
            selected
                .check_capacity(3, "MemAvailable: 4194303 kB\n")
                .is_err()
        );
        assert!(
            selected
                .check_capacity(3, "MemTotal: 4194304 kB\n")
                .is_err()
        );
        Ok(())
    }
}
