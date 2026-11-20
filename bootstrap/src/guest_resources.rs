//! Verify and carry Host-owned Guest settings through switch-root.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

pub use fvca_trial_authorization::guest_config::Resources;
use fvca_trial_authorization::guest_config::{self, ACTIVE, Configuration, LIMIT};

use crate::{invalid, recovery};

const SIGNED: &str = "/usr/lib/fvca/guest-vm-settings";
const RUNTIME_SUPPORT: &str = "/sysroot/usr/lib/fvca/guest-vm-settings-v2";
const O_NOFOLLOW: i32 = 0o400000;
const O_NONBLOCK: i32 = 0o4000;

#[cfg(feature = "libvirt")]
pub fn active() -> io::Result<Resources> {
    Ok(bound_record(
        Path::new(ACTIVE),
        0o600,
        &fs::read_to_string("/proc/cmdline")?,
    )?
    .map_or(Resources::DEFAULT, |(configuration, _)| {
        configuration.resources
    }))
}

#[cfg(feature = "libvirt")]
pub fn require_capacity(resources: Resources) -> io::Result<()> {
    let cpus = std::thread::available_parallelism()?.get();
    let memory = fs::read_to_string("/proc/meminfo")?;
    check_capacity(resources, cpus, &memory)
}

#[cfg(any(feature = "libvirt", test))]
fn check_capacity(resources: Resources, cpus: usize, memory: &str) -> io::Result<()> {
    resources.require_capacity(
        cpus,
        guest_config::host_memory_kib(memory, "MemAvailable:")?,
    )
}

fn open(path: &Path, mode: u32) -> io::Result<Option<File>> {
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
        || metadata.len() > LIMIT as u64
    {
        return Err(invalid("invalid Service Guest resource record file"));
    }
    Ok(Some(file))
}

fn bound_record(
    path: &Path,
    mode: u32,
    cmdline: &str,
) -> io::Result<Option<(Configuration, String)>> {
    let (mut file, binding) = match (open(path, mode)?, guest_config::binding(cmdline)?) {
        (None, None) => return Ok(None),
        (Some(file), Some(binding)) => (file, binding),
        _ => {
            return Err(invalid(
                "signed Service Guest configuration requires both a record and UKI binding",
            ));
        }
    };
    let mut payload = String::new();
    (&mut file)
        .take((LIMIT + 1) as u64)
        .read_to_string(&mut payload)?;
    let configuration = Configuration::parse(&payload)?;
    file.rewind()?;
    configuration.require_binding(&binding, &recovery::sha256(file)?)?;
    Ok(Some((configuration, payload)))
}

pub(crate) fn publish(cmdline: &str) -> io::Result<()> {
    if let Some((configuration, payload)) = bound_record(Path::new(SIGNED), 0o644, cmdline)? {
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
        println!("FVCA_GUEST_CONFIGURATION_BOUND {}", configuration.revision);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_host_cpu_and_memory_reserves() -> io::Result<()> {
        let selected = Resources {
            vcpus: 3,
            memory_mib: 2560,
        };
        let exact = "MemAvailable:      4194304 kB\n";
        check_capacity(selected, 3, exact)?;
        assert!(check_capacity(selected, 2, exact).is_err());
        assert!(check_capacity(selected, 3, "MemAvailable: 4194303 kB\n").is_err());
        assert!(check_capacity(selected, 3, "MemTotal: 4194304 kB\n").is_err());
        Ok(())
    }
}
