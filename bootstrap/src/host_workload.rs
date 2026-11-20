//! An unnumbered two-port workload bridge with a fixed QEMU TAP.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::Command;

use fvca_trial_authorization::{host_network, host_workload, workload_network};

use crate::net_setup::{self, IP};
use crate::{invalid, run};

pub const TAP: &str = "fvca-wl-tap";
const BRIDGE: &str = "fvca-wl-bridge";
const READY: &str = "/run/fvca/host-workload-network";
const SYS_NET: &str = "/sys/class/net";

fn rules(profile: &workload_network::Profile<'_>, port: u32) -> String {
    let mac = profile.uplink.mac;
    let address = profile.uplink.address;
    let outgoing = format!("iifname \"{TAP}\" oif {port}");
    let incoming = format!("iif {port} oifname \"{TAP}\"");
    let mut script = format!(
        "add chain bridge fvca_host workload_guard {{ type filter hook prerouting priority -300; policy accept; }}\n\
         add rule bridge fvca_host workload_guard iifname \"{TAP}\" ether saddr != {mac} drop\n\
         add rule bridge fvca_host workload_guard iif {port} ether saddr {mac} drop\n"
    );
    let neighbors: BTreeSet<_> = profile
        .ingress
        .iter()
        .chain(&profile.egress)
        .map(|&(_, peer, _)| peer)
        .filter(|&peer| profile.uplink.on_link(peer))
        .chain(profile.uplink.gateway)
        .collect();
    for peer in neighbors {
        writeln!(script, "add rule bridge fvca_host forward {outgoing} ether type arp ether saddr {mac} arp saddr ether {mac} arp saddr ip {address} arp daddr ip {peer} accept").unwrap();
        writeln!(script, "add rule bridge fvca_host forward {incoming} ether type arp ether daddr {{ {mac}, ff:ff:ff:ff:ff:ff }} arp saddr ip {peer} arp daddr ip {address} accept").unwrap();
    }
    let outgoing = format!(
        "add rule bridge fvca_host forward {outgoing} ether saddr {mac} ether type ip ip saddr {address}"
    );
    let incoming = format!(
        "add rule bridge fvca_host forward {incoming} ether daddr {mac} ether type ip ip daddr {address}"
    );
    for direction in [&outgoing, &incoming] {
        writeln!(
            script,
            "{direction} ct state established,related ct mark 0x46564341 accept"
        )
        .unwrap();
    }
    for &(protocol, peer, port) in &profile.ingress {
        writeln!(
            script,
            "{incoming} ip saddr {peer} {} dport {port} ct state new ct mark set 0x46564341 accept",
            protocol.nft()
        )
        .unwrap();
    }
    for &(protocol, peer, port) in &profile.egress {
        writeln!(
            script,
            "{outgoing} ip daddr {peer} {} dport {port} ct state new ct mark set 0x46564341 accept",
            protocol.nft()
        )
        .unwrap();
    }
    script
}

fn link(name: &OsStr, settings: &[&str]) -> io::Result<()> {
    run(Command::new(IP)
        .args(["link", "set", "dev"])
        .arg(name)
        .args(settings))
}

fn attach(profile: &workload_network::Profile<'_>, port: &OsStr, index: u32) -> io::Result<()> {
    let mtu = profile.mtu.to_string();
    run(Command::new(IP).args([
        "link",
        "add",
        "name",
        BRIDGE,
        "type",
        "bridge",
        "stp_state",
        "0",
        "mcast_snooping",
        "0",
    ]))?;
    run(Command::new(IP).args([
        "tuntap", "add", "dev", TAP, "mode", "tap", "user", "107", "group", "107",
    ]))?;
    run(Command::new(IP).args(["address", "flush", "dev"]).arg(port))?;
    for dev in [BRIDGE.as_ref(), TAP.as_ref(), port] {
        link(dev, &["addrgenmode", "none", "mtu", &mtu])?;
    }
    for dev in [TAP.as_ref(), port] {
        link(dev, &["master", BRIDGE])?;
    }
    net_setup::apply_filter(None, &rules(profile, index))?;
    for dev in [BRIDGE.as_ref(), TAP.as_ref(), port] {
        link(dev, &["up"])?;
    }
    Ok(())
}

pub fn activate(cmdline: &str) -> io::Result<()> {
    let digest = host_workload::binding(cmdline)?;
    let raw = net_setup::signed_record(host_workload::RECORD, host_workload::LIMIT, digest)?;
    let (Some(raw), Some(digest)) = (raw.as_deref(), digest) else {
        net_setup::signed_record(host_workload::GUEST_RECORD, workload_network::LIMIT, None)?;
        return Ok(());
    };
    let support =
        fs::symlink_metadata(Path::new("/sysroot/usr/lib/fvca").join(host_workload::SUPPORT))?;
    if !support.is_file()
        || support.len() != 0
        || !Path::new("/usr/lib/fvca/guest-launch").is_file()
    {
        return Err(invalid(
            "a workload bridge requires the verified launcher and registered Guest",
        ));
    }
    let enrolled = host_workload::Enrollment::parse(raw)?;
    let guest = net_setup::signed_record(
        host_workload::GUEST_RECORD,
        workload_network::LIMIT,
        Some(enrolled.guest),
    )?
    .ok_or_else(|| invalid("missing enrolled Guest workload record"))?;
    let profile = workload_network::Profile::parse(&guest)?;
    let management = net_setup::signed_record(
        host_network::RECORD,
        host_network::LIMIT,
        host_network::binding(cmdline)?,
    )?;
    let management = management
        .as_deref()
        .map(host_network::Profile::parse)
        .transpose()?;
    enrolled.validate(&profile, management.map(|profile| profile.uplink))?;
    let (device, index) = net_setup::wait_for_interface(enrolled.port, false)?;
    net_setup::require_down(&device)?;
    if device.join("master").try_exists()?
        || Path::new(SYS_NET).join(BRIDGE).try_exists()?
        || Path::new(SYS_NET).join(TAP).try_exists()?
    {
        return Err(invalid("workload bridge devices must be dedicated at boot"));
    }
    let port = device.file_name().expect("interface path has a basename");
    for module in ["tun", "nft_meta_bridge", "nf_conntrack_bridge"] {
        run(Command::new("/usr/bin/modprobe").args(["--ignore-install", module]))?;
    }
    let result = attach(&profile, port, index).and_then(|()| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(READY)?;
        writeln!(
            file,
            "FVCA-HOST-WORKLOAD-READY-1\nhost={digest}\nguest={}\nmac={}",
            enrolled.guest, profile.uplink.mac
        )
    });
    if let Err(error) = result {
        let _ = link(port, &["down"]);
        if Path::new(SYS_NET).join(TAP).exists() {
            let _ = run(Command::new(IP).args(["tuntap", "del", "dev", TAP, "mode", "tap"]));
        }
        if Path::new(SYS_NET).join(BRIDGE).exists() {
            let _ = run(Command::new(IP).args(["link", "delete", "dev", BRIDGE]));
        }
        return Err(error);
    }
    println!("FVCA_HOST_WORKLOAD_READY {} {digest}", enrolled.port.pci);
    Ok(())
}

pub fn guest_mac(guest_cmdline: &str) -> io::Result<Option<String>> {
    let cmdline = fs::read_to_string("/proc/cmdline")?;
    let Some(digest) = host_workload::binding(&cmdline)? else {
        host_workload::require_guest(None, guest_cmdline)?;
        return Ok(None);
    };
    let metadata = fs::symlink_metadata(READY)?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != 0o600
        || metadata.len() > 256
        || fs::canonicalize(Path::new(SYS_NET).join(TAP).join("master"))?.file_name()
            != Some(BRIDGE.as_ref())
    {
        return Err(invalid(
            "the registered Guest TAP differs from the verified Host bridge",
        ));
    }
    let mut ready = String::new();
    fs::File::open(READY)?
        .take(257)
        .read_to_string(&mut ready)?;
    host_workload::ready_mac(&ready, digest, guest_cmdline).map(|mac| Some(mac.to_owned()))
}
