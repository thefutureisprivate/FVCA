//! Install the fixed Host packet policy before configuring the enrolled NIC.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::process::Command;

use fvca_trial_authorization::{
    host_network::{self, Profile, Uplink as Identity},
    management_binding,
};

use crate::net_setup::{self, IP, SIGNED};
use crate::{backup_policy, invalid, run};

struct Uplink<'a> {
    profile: Identity<'a>,
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
    net_setup::apply_filter(None, &rules(None))?;
    let digest = host_network::binding(cmdline)?;
    let raw = net_setup::signed_record(host_network::RECORD, host_network::LIMIT, digest)?;
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
    let profile = profile.uplink;
    let (device, index) = net_setup::wait_for_interface(&profile, false).map_err(|error| {
        if error.kind() == io::ErrorKind::TimedOut {
            invalid("the signed Host management NIC is unavailable")
        } else {
            error
        }
    })?;
    net_setup::require_down(&device)?;
    let name = device.file_name().expect("interface path has a basename");
    let uplink = Uplink {
        profile,
        index,
        ingress,
        egress: egress()?,
    };
    let ip = || Command::new(IP);
    let local = net_setup::address(ip, name, profile, None)?;
    run(ip().args(["link", "set", "dev"]).arg(name).arg("up"))?;
    if let Err(error) = net_setup::route(ip, name, profile)
        .and_then(|()| net_setup::apply_filter(None, &rules(Some(&uplink))))
    {
        let _ = run(ip().args(["link", "set", "dev"]).arg(name).arg("down"));
        return Err(error);
    }
    println!("FVCA_HOST_NETWORK_READY {} {local}", profile.pci);
    Ok(())
}
