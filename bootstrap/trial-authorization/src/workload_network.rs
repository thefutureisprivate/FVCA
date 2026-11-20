//! A site-approved IPv4 uplink dedicated to one Service Guest workload.

use std::collections::BTreeSet;
use std::io;
use std::net::Ipv4Addr;

use crate::host_network::{Uplink, field, ipv4, optional_address};
use crate::{digest, invalid, signed_argument};

pub const ARGUMENT: &str = "fvca.workload_network";
pub const RECORD: &str = "workload-network";
pub const LIMIT: usize = 4096;

pub fn binding(cmdline: &str) -> io::Result<Option<&str>> {
    signed_argument(cmdline, ARGUMENT)?
        .map(|value| digest(value, ""))
        .transpose()
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub enum Transport {
    Tcp,
    Udp,
}

impl Transport {
    pub fn nft(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

pub type Endpoint = (Transport, Ipv4Addr, u16);

pub struct Profile<'a> {
    pub uplink: Uplink<'a>,
    pub mtu: u16,
    pub dns: Option<Ipv4Addr>,
    pub ingress: BTreeSet<Endpoint>,
    pub egress: BTreeSet<Endpoint>,
}

fn peer(uplink: Uplink<'_>, address: Ipv4Addr) -> io::Result<Ipv4Addr> {
    let reachable = if uplink.on_link(address) {
        uplink.usable(address)
    } else {
        uplink.gateway.is_some()
    };
    if address == uplink.address || !reachable {
        return Err(invalid(
            "workload peer has no route through the signed uplink",
        ));
    }
    Ok(address)
}

fn endpoint(uplink: Uplink<'_>, raw: &str) -> io::Result<Endpoint> {
    let mut fields = raw.split(',');
    let protocol = match fields.next() {
        Some("tcp") => Transport::Tcp,
        Some("udp") => Transport::Udp,
        _ => return Err(invalid("expected a TCP or UDP workload peer")),
    };
    let Some(address) = fields.next() else {
        return Err(invalid("missing workload peer address"));
    };
    let Some(port) = fields.next() else {
        return Err(invalid("missing workload peer port"));
    };
    let number: u16 = port.parse().map_err(io::Error::other)?;
    if number == 0 || number.to_string() != port || fields.next().is_some() {
        return Err(invalid("invalid workload peer port"));
    }
    Ok((protocol, peer(uplink, ipv4(address)?)?, number))
}

impl<'a> Profile<'a> {
    pub fn parse(raw: &'a str) -> io::Result<Self> {
        if raw.len() > LIMIT || !raw.ends_with('\n') || raw.contains('\r') {
            return Err(invalid(
                "invalid signed workload network record size or line endings",
            ));
        }
        let mut lines = raw.lines();
        let [
            Some("FVCA-GUEST-WORKLOAD-NETWORK-1"),
            Some(pci),
            Some(mac),
            Some(cidr),
            Some(gateway),
            Some(mtu),
            Some(dns),
        ] = std::array::from_fn(|_| lines.next())
        else {
            return Err(invalid("expected the canonical workload network record"));
        };
        let uplink = Uplink::parse(pci, mac, cidr, gateway)?;
        let raw_mtu = field(mtu, "mtu=")?;
        let mtu: u16 = raw_mtu.parse().map_err(io::Error::other)?;
        if !(1280..=1500).contains(&mtu) || mtu.to_string() != raw_mtu {
            return Err(invalid("workload MTU must be between 1280 and 1500"));
        }
        let dns = optional_address(field(dns, "dns=")?)?
            .map(|address| peer(uplink, address))
            .transpose()?;
        let mut ingress = BTreeSet::new();
        let mut egress = BTreeSet::new();
        for line in lines {
            let (rules, value) = if let Some(value) = line.strip_prefix("ingress=") {
                (&mut ingress, value)
            } else {
                (&mut egress, field(line, "egress=")?)
            };
            let rule = endpoint(uplink, value)?;
            if rules.len() == 32 || !rules.insert(rule) {
                return Err(invalid("too many or duplicate workload peer rules"));
            }
        }
        if let Some(address) = dns {
            egress.extend([(Transport::Tcp, address, 53), (Transport::Udp, address, 53)]);
        }
        Ok(Self {
            uplink,
            mtu,
            dns,
            ingress,
            egress,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECORD: &str = "FVCA-GUEST-WORKLOAD-NETWORK-1\npci=0000:00:06.0\nmac=52:54:00:10:20:30\naddress=192.168.44.15/24\ngateway=none\nmtu=1400\ndns=192.168.44.53\ningress=tcp,192.168.44.20,443\negress=udp,192.168.44.70,123\n";

    #[test]
    fn permits_only_canonical_routes_and_exact_peer_ports() -> io::Result<()> {
        let profile = Profile::parse(RECORD)?;
        let dns = Ipv4Addr::new(192, 168, 44, 53);
        assert_eq!(profile.mtu, 1400);
        assert_eq!(profile.dns, Some(dns));
        assert!(profile.egress.contains(&(Transport::Tcp, dns, 53)));
        assert!(profile.egress.contains(&(Transport::Udp, dns, 53)));
        for invalid in [
            RECORD.replace("192.168.44.20,443", "192.168.45.20,443"),
            RECORD.replace("192.168.44.20,443", "192.168.44.255,443"),
            RECORD.replace("192.168.44.20,443", "192.168.44.15,443"),
            RECORD.replace("192.168.44.20,443", "192.168.44.20,0443"),
            RECORD.replace("mtu=1400", "mtu=1501"),
            format!("{RECORD}ingress=tcp,192.168.44.20,443\n"),
        ] {
            assert!(Profile::parse(&invalid).is_err(), "{invalid}");
        }
        Ok(())
    }
}
