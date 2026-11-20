//! Apply the measured Service Guest workload network before switch-root.

use std::fmt::Write as _;
use std::fs;
use std::io::{self, Write as _};
use std::os::unix::fs::OpenOptionsExt;
use std::process::Command;

use fvca_trial_authorization::workload_network::{self, Profile};

use crate::net_setup::{self, IP};
use crate::{invalid, run};

const NAMESPACE: &str = "fvca-workload";
const NAMESPACE_PATH: &str = "/run/netns/fvca-workload";
const UPLINK: &str = "fvca-uplink";
const READY: &str = "/run/fvca/workload-network";

fn rules(profile: Option<&Profile<'_>>) -> String {
    let mut rules = String::from(concat!(
        "destroy table inet fvca_guest\n",
        "add table inet fvca_guest\n",
        "add chain inet fvca_guest input { type filter hook input priority filter; policy drop; }\n",
        "add chain inet fvca_guest output { type filter hook output priority filter; policy drop; }\n",
        "add chain inet fvca_guest forward { type filter hook forward priority filter; policy drop; }\n",
        "add rule inet fvca_guest input iifname \"lo\" accept\n",
        "add rule inet fvca_guest output oifname \"lo\" accept\n",
    ));
    if let Some(profile) = profile {
        let address = profile.uplink.address;
        let input =
            format!("add rule inet fvca_guest input iifname \"{UPLINK}\" ip daddr {address}");
        let output =
            format!("add rule inet fvca_guest output oifname \"{UPLINK}\" ip saddr {address}");
        writeln!(rules, "{input} ct state established,related accept").unwrap();
        writeln!(rules, "{output} ct state established,related accept").unwrap();
        for &(protocol, peer, port) in &profile.ingress {
            writeln!(
                rules,
                "{input} ip saddr {peer} {} dport {port} ct state new accept",
                protocol.nft()
            )
            .unwrap();
        }
        for &(protocol, peer, port) in &profile.egress {
            writeln!(
                rules,
                "{output} ip daddr {peer} {} dport {port} ct state new accept",
                protocol.nft()
            )
            .unwrap();
        }
    }
    rules
}

fn ip() -> Command {
    net_setup::in_namespace(NAMESPACE_PATH, IP)
}

fn connect(profile: &Profile<'_>, digest: &str, name: &std::ffi::OsStr) -> io::Result<()> {
    net_setup::apply_filter(Some(NAMESPACE_PATH), &rules(Some(profile)))?;
    run(
        net_setup::in_namespace(NAMESPACE_PATH, "/usr/lib/systemd/systemd-sysctl").args([
            "--strict",
            "--verify",
            "--inline",
            "net.ipv4.ip_unprivileged_port_start=0",
        ]),
    )?;
    run(Command::new(IP)
        .args(["link", "set", "dev"])
        .arg(name)
        .args(["netns", NAMESPACE, "name", UPLINK]))?;
    let address = net_setup::address(ip, UPLINK.as_ref(), profile.uplink, Some(profile.mtu))?;
    run(ip().args(["link", "set", "dev", "lo", "up"]))?;
    run(ip().args(["link", "set", "dev", UPLINK, "up"]))?;
    net_setup::route(ip, UPLINK.as_ref(), profile.uplink)?;
    fs::create_dir_all("/run/fvca")?;
    let dns = profile
        .dns
        .map_or_else(|| "none".into(), |address| address.to_string());
    let mut ready = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(READY)?;
    writeln!(ready, "profile=sha256:{digest}\ndns={dns}")?;
    println!(
        "FVCA_WORKLOAD_NETWORK_READY {} {address}",
        profile.uplink.pci
    );
    Ok(())
}

pub fn activate(cmdline: &str, workload_trust: bool) -> io::Result<()> {
    net_setup::apply_filter(None, &rules(None))?;
    let digest = workload_network::binding(cmdline)?;
    let raw = net_setup::signed_record(workload_network::RECORD, workload_network::LIMIT, digest)?;
    let (Some(raw), Some(digest)) = (raw.as_deref(), digest) else {
        return Ok(());
    };
    if !workload_trust {
        return Err(invalid("a workload uplink requires signed workload trust"));
    }
    let profile = Profile::parse(raw)?;
    let (device, _) = net_setup::wait_for_interface(profile.uplink.nic(), true)?;
    net_setup::require_down(&device)?;
    let name = device.file_name().expect("interface path has a basename");
    run(Command::new(IP).args(["netns", "add", NAMESPACE]))?;
    if let Err(error) = connect(&profile, digest, name) {
        let _ = run(ip().args(["link", "set", "dev", UPLINK, "down"]));
        let _ = run(Command::new(IP).args(["netns", "del", NAMESPACE]));
        return Err(error);
    }
    Ok(())
}
