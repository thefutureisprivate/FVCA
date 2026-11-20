//! Bootstrap network operations shared by the Host and Service Guest.

use std::fs::{self, File};
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use fvca_trial_authorization::host_network::Uplink as Identity;

use crate::{invalid, recovery, run};

pub(crate) const SIGNED: &str = "/usr/lib/fvca";
pub(crate) const IP: &str = "/usr/bin/ip";
const NET: &str = "/sys/class/net";
const NFT: &str = "/usr/bin/nft";

pub(crate) fn in_namespace(path: &str, program: &str) -> Command {
    let mut command = Command::new("/usr/bin/nsenter");
    command.arg(format!("--net={path}")).args(["--", program]);
    command
}

pub(crate) fn apply_filter(namespace: Option<&str>, rules: &str) -> io::Result<()> {
    let mut command = namespace.map_or_else(|| Command::new(NFT), |path| in_namespace(path, NFT));
    let mut child = command
        .env_clear()
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .spawn()?;
    let sent = child
        .stdin
        .take()
        .expect("nft has a pipe")
        .write_all(rules.as_bytes());
    if !child.wait()?.success() {
        return Err(invalid("nft rejected the signed network policy"));
    }
    sent
}

pub(crate) fn signed_record(
    name: &str,
    limit: usize,
    expected: Option<&str>,
) -> io::Result<Option<String>> {
    let path = Path::new(SIGNED).join(name);
    let Some(expected) = expected else {
        return if path.try_exists()? {
            Err(invalid("the network record lacks a signed digest"))
        } else {
            Ok(None)
        };
    };
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.len() > limit as u64
        || recovery::sha256(file.try_clone()?)? != expected
    {
        return Err(invalid("the network record differs from its signed UKI"));
    }
    file.rewind()?;
    let mut raw = String::new();
    file.take((limit + 1) as u64).read_to_string(&mut raw)?;
    Ok(Some(raw))
}

fn initialized_interface(
    profile: &Identity<'_>,
    virtio: bool,
) -> io::Result<Option<(PathBuf, u32)>> {
    let mut selected = None;
    for entry in fs::read_dir(NET)? {
        let path = entry?.path();
        let candidate = match inspect_interface(&path, profile, virtio) {
            Ok(candidate) => candidate,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if let Some(index) = candidate
            && selected.replace((path, index)).is_some()
        {
            return Err(invalid("multiple interfaces match the signed uplink"));
        }
    }
    Ok(selected)
}

fn inspect_interface(path: &Path, profile: &Identity<'_>, virtio: bool) -> io::Result<Option<u32>> {
    let device = fs::read_link(path.join("device"))?;
    let pci = if virtio {
        let sys_device = path.join("device");
        let driver = fs::read_link(sys_device.join("driver"))?;
        if driver.file_name() != Some("virtio_net".as_ref()) {
            return Ok(None);
        }
        fs::canonicalize(sys_device)?
            .parent()
            .map(Path::to_path_buf)
    } else {
        Some(device)
    };
    if pci.as_deref().and_then(Path::file_name) != Some(profile.pci.as_ref())
        || fs::read_to_string(path.join("type"))?.trim_end() != "1"
        || fs::read_to_string(path.join("addr_assign_type"))?.trim_end() != "0"
        || fs::read_to_string(path.join("address"))?.trim_end() != profile.mac
    {
        return Ok(None);
    }
    let index: u32 = fs::read_to_string(path.join("ifindex"))?
        .trim_end()
        .parse()
        .map_err(io::Error::other)?;
    let properties = fs::read_to_string(format!("/run/udev/data/n{index}"))?;
    if properties
        .lines()
        .any(|line| matches!(line, "E:ID_PROCESSING=1" | "E:ID_RENAMING=1"))
    {
        return Ok(None);
    }
    Ok(path.try_exists()?.then_some(index))
}

pub(crate) fn wait_for_interface(
    profile: &Identity<'_>,
    virtio: bool,
) -> io::Result<(PathBuf, u32)> {
    let deadline = Instant::now() + Duration::from_secs(12);
    loop {
        if let Some(device) = initialized_interface(profile, virtio)? {
            return Ok(device);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the signed network NIC is unavailable",
            ));
        }
        thread::sleep(Duration::from_millis(100));
    }
}

pub(crate) fn require_down(device: &Path) -> io::Result<()> {
    let flags = fs::read_to_string(device.join("flags"))?;
    let flags = u32::from_str_radix(flags.trim_end().trim_start_matches("0x"), 16)
        .map_err(io::Error::other)?;
    if flags & 1 != 0 {
        return Err(invalid(
            "the signed uplink must start administratively down",
        ));
    }
    Ok(())
}

pub(crate) fn address(
    ip: impl Fn() -> Command,
    name: &std::ffi::OsStr,
    profile: Identity<'_>,
    mtu: Option<u16>,
) -> io::Result<String> {
    let mut link = ip();
    link.args(["link", "set", "dev"])
        .arg(name)
        .args(["addrgenmode", "none"]);
    if let Some(mtu) = mtu {
        link.arg("mtu").arg(mtu.to_string());
    }
    run(&mut link)?;
    let local = format!("{}/{}", profile.address, profile.prefix);
    run(ip().args(["-4", "address", "add", &local, "dev"]).arg(name))?;
    Ok(local)
}

pub(crate) fn route(
    ip: impl Fn() -> Command,
    name: &std::ffi::OsStr,
    profile: Identity<'_>,
) -> io::Result<()> {
    if let Some(router) = profile.gateway {
        run(ip()
            .args([
                "-4",
                "route",
                "add",
                "default",
                "via",
                &router.to_string(),
                "dev",
            ])
            .arg(name))?;
    }
    Ok(())
}
