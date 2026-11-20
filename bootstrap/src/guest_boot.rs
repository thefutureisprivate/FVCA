//! Exact launch selection authenticated by the Hypervisor UKI.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::{invalid, runtime};

pub const BOOT: &str = "/run/fvca/guest-boot";
pub const SELECTION: &str = "/run/fvca/guest-launch";
const SOURCE: &str = "/usr/lib/fvca/guest-launch";
const SIGNATURE: &str = "/usr/lib/fvca/guest-launch.p7s";
pub const FILES: [&str; 9] = [
    "boot.efi", "linux", "initrd", "cmdline", "domain.xml", "core.raw", "runtime.raw", "release.json", "release.p7s",
];

pub struct Selection<'a> {
    pub bundle: &'a str,
    pub core: &'a str,
    pub runtime: &'a str,
    pub checksums: &'a str,
}

fn field<'a>(line: Option<&'a str>, prefix: &str) -> io::Result<&'a str> {
    let content = line.and_then(|line| line.strip_prefix(prefix))
        .ok_or_else(|| invalid("invalid Guest launch selection field"))?;
    runtime::hash(content)
}

pub fn parse(payload: &str) -> io::Result<Selection<'_>> {
    let mut lines = payload.split('\n');
    if lines.next() != Some("FVCA-GUEST-LAUNCH-1") {
        return Err(invalid("unexpected Guest launch selection version"));
    }
    let bundle = field(lines.next(), "bundle=")?;
    let core = field(lines.next(), "core=")?;
    let runtime = field(lines.next(), "runtime=")?;
    for name in FILES {
        let (digest, selected) = lines.next().and_then(|line| line.split_once("  "))
            .ok_or_else(|| invalid("incomplete Guest boot bundle inventory"))?;
        runtime::hash(digest)?;
        if name != selected {
            return Err(invalid("unexpected Guest boot bundle inventory"));
        }
    }
    if lines.next() != Some("") || lines.next().is_some() {
        return Err(invalid("unexpected fields in Guest launch selection"));
    }
    let checksums = payload.strip_prefix(&format!("FVCA-GUEST-LAUNCH-1\nbundle={bundle}\ncore={core}\nruntime={runtime}\n"))
        .ok_or_else(|| invalid("invalid Guest launch selection"))?;
    Ok(Selection { bundle, core, runtime, checksums })
}

pub fn activate_if_selected(auto_start: bool, devices: Option<&(PathBuf, PathBuf)>) -> io::Result<()> {
    let payload = match fs::read_to_string(SOURCE) {
        Ok(payload) => payload,
        Err(error) if error.kind() == io::ErrorKind::NotFound && !Path::new(SIGNATURE).try_exists()? => return Ok(()),
        Err(error) => return Err(error),
    };
    let selection = parse(&payload)?;
    runtime::mount_verified("guest-boot", "Guest boot bundle", selection.bundle, Path::new(SIGNATURE),
                            Path::new(BOOT), "ro,nodev,nosuid,noexec", devices)?;
    fs::write(SELECTION, payload)?;
    if !auto_start {
        return Ok(());
    }
    let control = Path::new("/run/systemd/system");
    let dropin = control.join("fvca-base-ready.service.d");
    let wants = control.join("fvca-base-ready.service.wants");
    fs::create_dir_all(&dropin)?;
    fs::create_dir_all(&wants)?;
    fs::write(dropin.join("20-guest-ready.conf"), concat!(
        "[Service]\n",
        "ExecStartPre=/usr/bin/systemctl --quiet is-active fvca-service-guest.service\n",
    ))?;
    std::os::unix::fs::symlink(
        "/usr/lib/systemd/system/fvca-service-guest.service",
        wants.join("fvca-service-guest.service"),
    )?;
    Ok(())
}
