//! Install the fixed Host packet policy before configuring the enrolled NIC.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{self, Read, Seek, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use fvca_trial_authorization::{
    host_network::{self, Profile},
    management_binding,
};

use crate::{backup_policy, invalid, recovery, run};

const SIGNED: &str = "/usr/lib/fvca";
const NET: &str = "/sys/class/net";
const IP: &str = "/usr/bin/ip";
const NFT: &str = "/usr/bin/nft";

struct Uplink<'a> {
    profile: Profile<'a>,
    index: u32,
    ingress: Option<(Ipv4Addr, u16)>,
    egress: BTreeSet<(Ipv4Addr, u16)>,
}

fn rules(uplink: Option<&Uplink<'_>>) -> String {
    let mut rules = String::from(concat!(
        "destroy table inet fvca_host\n",
        "destroy table bridge fvca_host\n",
        "add table inet fvca_host\n",
        "add table bridge fvca_host\n",
    ));
    for family in ["inet", "bridge"] {
        for chain in ["input", "output", "forward"] {
            writeln!(rules, "add chain {family} fvca_host {chain} {{ type filter hook {chain} priority filter; policy drop; }}")
                .expect("writing to a string cannot fail");
        }
    }
    rules.push_str(concat!(
        "add rule inet fvca_host input iifname \"lo\" accept\n",
        "add rule inet fvca_host output oifname \"lo\" accept\n",
    ));
    if let Some(uplink) = uplink {
        let index = uplink.index;
        let address = uplink.profile.address;
        writeln!(rules, "add rule inet fvca_host input iif {index} ip daddr {address} ct state established,related accept").unwrap();
        writeln!(rules, "add rule inet fvca_host output oif {index} ip saddr {address} ct state established,related accept").unwrap();
        if let Some((peer, port)) = uplink.ingress {
            writeln!(rules, "add rule inet fvca_host input iif {index} ip saddr {peer} ip daddr {address} tcp dport {port} ct state new accept").unwrap();
        }
        for (peer, port) in &uplink.egress {
            writeln!(rules, "add rule inet fvca_host output oif {index} ip saddr {address} ip daddr {peer} tcp dport {port} ct state new accept").unwrap();
        }
    }
    rules
}

fn filter(uplink: Option<&Uplink<'_>>) -> io::Result<()> {
    let mut child = Command::new(NFT)
        .env_clear()
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .spawn()?;
    let sent = child
        .stdin
        .take()
        .expect("nft has a pipe")
        .write_all(rules(uplink).as_bytes());
    if !child.wait()?.success() {
        return Err(invalid("nft rejected the Host network policy"));
    }
    sent
}

fn signed_profile(cmdline: &str) -> io::Result<Option<String>> {
    let expected = host_network::binding(cmdline)?;
    let path = Path::new(SIGNED).join(host_network::RECORD);
    let Some(expected) = expected else {
        return if path.try_exists()? {
            Err(invalid("the Host network record lacks a signed digest"))
        } else {
            Ok(None)
        };
    };
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.len() > host_network::LIMIT as u64
        || recovery::sha256(file.try_clone()?)? != expected
    {
        return Err(invalid(
            "the Host network record differs from its signed UKI",
        ));
    }
    file.rewind()?;
    let mut raw = String::new();
    file.take((host_network::LIMIT + 1) as u64)
        .read_to_string(&mut raw)?;
    Ok(Some(raw))
}

fn initialized_interface(profile: &Profile<'_>) -> io::Result<Option<(PathBuf, u32)>> {
    let mut selected = None;
    for entry in fs::read_dir(NET)? {
        let path = entry?.path();
        let candidate = match inspect_interface(&path, profile) {
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

fn inspect_interface(path: &Path, profile: &Profile<'_>) -> io::Result<Option<u32>> {
    let device = fs::read_link(path.join("device"))?;
    if device.file_name() != Some(profile.pci.as_ref())
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
    Ok(path.exists().then_some(index))
}

fn wait_for_interface(profile: &Profile<'_>) -> io::Result<(PathBuf, u32)> {
    let deadline = Instant::now() + Duration::from_secs(12);
    loop {
        if let Some(device) = initialized_interface(profile)? {
            return Ok(device);
        }
        if Instant::now() >= deadline {
            return Err(invalid("the signed Host management NIC is unavailable"));
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn tcp_endpoint(address: IpAddr, port: u16) -> io::Result<Option<(Ipv4Addr, u16)>> {
    if address.is_loopback() {
        return Ok(None);
    }
    let IpAddr::V4(address) = address else {
        return Err(invalid(
            "the Host uplink cannot route this enrolled IPv6 endpoint",
        ));
    };
    if address.is_unspecified() || address.is_multicast() || address.is_broadcast() {
        return Err(invalid("invalid Host network destination"));
    }
    Ok(Some((address, port)))
}

fn optional_file(name: &str) -> io::Result<Option<String>> {
    match fs::read_to_string(Path::new(SIGNED).join(name)) {
        Ok(data) => Ok(Some(data)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn egress() -> io::Result<BTreeSet<(Ipv4Addr, u16)>> {
    let mut selected = BTreeSet::new();
    for name in [
        "os-update-depot",
        "guest-os-update-depot",
        "firmware-update-depot",
    ] {
        if let Some(raw) = optional_file(name)?
            && raw != "local\n"
        {
            let address = raw.trim_end().parse().map_err(io::Error::other)?;
            selected.extend(tcp_endpoint(address, 443)?);
        }
    }
    if let Some(raw) = optional_file("vm-backup-policy")? {
        let endpoint = backup_policy::parse(&raw)?.endpoint;
        selected.extend(tcp_endpoint(endpoint.ip(), endpoint.port())?);
    }
    Ok(selected)
}

pub fn activate(cmdline: &str) -> io::Result<()> {
    filter(None)?;
    let raw = signed_profile(cmdline)?;
    let profile = raw.as_deref().map(Profile::parse).transpose()?;
    let binding = management_binding(cmdline)?.map(|(_, address)| address);
    let ingress = host_network::management_rule(profile.as_ref(), binding)?;
    let Some(profile) = profile else {
        return Ok(());
    };
    let support = fs::symlink_metadata("/sysroot/usr/lib/fvca/host-network-v1")?;
    if !support.is_file() || support.len() != 0 {
        return Err(invalid(
            "the verified runtime cannot preserve the signed Host uplink",
        ));
    }
    let (device, index) = wait_for_interface(&profile)?;
    let flags = fs::read_to_string(device.join("flags"))?;
    let flags = u32::from_str_radix(flags.trim_end().trim_start_matches("0x"), 16)
        .map_err(io::Error::other)?;
    if flags & 1 != 0 {
        return Err(invalid(
            "the management uplink must start administratively down",
        ));
    }
    let name = device.file_name().expect("interface path has a basename");
    let uplink = Uplink {
        profile,
        index,
        ingress,
        egress: egress()?,
    };
    run(Command::new(IP)
        .args(["link", "set", "dev"])
        .arg(name)
        .args(["addrgenmode", "none"]))?;
    let local = format!("{}/{}", profile.address, profile.prefix);
    run(Command::new(IP)
        .args(["-4", "address", "add", &local, "dev"])
        .arg(name))?;
    run(Command::new(IP)
        .args(["link", "set", "dev"])
        .arg(name)
        .arg("up"))?;
    let routing = if let Some(router) = profile.gateway {
        run(Command::new(IP)
            .args([
                "-4",
                "route",
                "add",
                "default",
                "via",
                &router.to_string(),
                "dev",
            ])
            .arg(name))
    } else {
        Ok(())
    };
    if let Err(error) = routing.and_then(|()| filter(Some(&uplink))) {
        let _ = run(Command::new(IP)
            .args(["link", "set", "dev"])
            .arg(name)
            .arg("down"));
        return Err(error);
    }
    println!("FVCA_HOST_NETWORK_READY {} {local}", profile.pci);
    Ok(())
}
