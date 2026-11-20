//! Canonical site network selection bound to the Hypervisor UKI.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};

use crate::{digest, invalid, signed_argument};

pub const ARGUMENT: &str = "fvca.host_network";
pub const RECORD: &str = "host-network";
pub const LIMIT: usize = 512;

pub fn binding(cmdline: &str) -> io::Result<Option<&str>> {
    signed_argument(cmdline, ARGUMENT)?
        .map(|value| digest(value, ""))
        .transpose()
}

#[derive(Clone, Copy)]
pub struct Profile<'a> {
    pub uplink: Uplink<'a>,
    pub operator: Option<Ipv4Addr>,
}

#[derive(Clone, Copy)]
pub struct Uplink<'a> {
    pub pci: &'a str,
    pub mac: &'a str,
    pub address: Ipv4Addr,
    pub prefix: u8,
    pub gateway: Option<Ipv4Addr>,
}

fn unicast(address: Ipv4Addr) -> bool {
    address.octets()[0] != 0
        && address.octets()[0] < 224
        && !address.is_loopback()
        && !address.is_link_local()
}

pub(crate) fn ipv4(value: &str) -> io::Result<Ipv4Addr> {
    let address = value.parse().map_err(io::Error::other)?;
    if !unicast(address) || address.to_string() != value {
        return Err(invalid(
            "the Host network requires a canonical unicast IPv4 address",
        ));
    }
    Ok(address)
}

pub(crate) fn optional_address(value: &str) -> io::Result<Option<Ipv4Addr>> {
    (value != "none").then(|| ipv4(value)).transpose()
}

pub(crate) fn field<'a>(line: &'a str, key: &str) -> io::Result<&'a str> {
    line.strip_prefix(key)
        .ok_or_else(|| invalid("invalid Host network field"))
}

impl<'a> Profile<'a> {
    pub fn parse(raw: &'a str) -> io::Result<Self> {
        if raw.len() > LIMIT {
            return Err(invalid(
                "the signed Host network record exceeds its size bound",
            ));
        }
        let lines: Vec<_> = raw.split('\n').collect();
        let ["FVCA-HOST-NETWORK-1", pci, mac, cidr, gateway, operator, ""] = lines.as_slice()
        else {
            return Err(invalid("expected the canonical Host network record"));
        };
        let uplink = Uplink::parse(pci, mac, cidr, gateway)?;
        let operator = optional_address(field(operator, "operator=")?)?;
        if operator.is_some_and(|ip| {
            !ip.is_private() || ip == uplink.address || (uplink.on_link(ip) && !uplink.usable(ip))
        }) {
            return Err(invalid("invalid Host management peer"));
        }
        Ok(Self { uplink, operator })
    }
}

impl<'a> Uplink<'a> {
    pub(crate) fn parse(pci: &'a str, mac: &'a str, cidr: &str, gateway: &str) -> io::Result<Self> {
        let pci = field(pci, "pci=")?;
        let mac = field(mac, "mac=")?;
        if !hardware_field(pci, b"hhhh:hh:hh.f")
            || !hardware_field(mac, b"hh:hh:hh:hh:hh:hh")
            || u8::from_str_radix(&mac[..2], 16).map_or(true, |first| first & 1 != 0)
            || mac == "00:00:00:00:00:00"
            || u8::from_str_radix(&pci[8..10], 16).map_or(true, |slot| slot > 31)
        {
            return Err(invalid("invalid enrolled PCI address or Ethernet MAC"));
        }
        let (address, prefix) = field(cidr, "address=")?
            .split_once('/')
            .ok_or_else(|| invalid("the Host address requires a subnet prefix"))?;
        let address = ipv4(address)?;
        let bits: u8 = prefix.parse().map_err(io::Error::other)?;
        if !address.is_private() || !(1..=32).contains(&bits) || bits.to_string() != prefix {
            return Err(invalid(
                "the management uplink requires a private IPv4 subnet",
            ));
        }
        let gateway = optional_address(field(gateway, "gateway=")?)?;
        let uplink = Self {
            pci,
            mac,
            address,
            prefix: bits,
            gateway,
        };
        if !uplink.usable(address)
            || gateway.is_some_and(|ip| !uplink.usable(ip) || ip == address || !uplink.on_link(ip))
        {
            return Err(invalid("invalid uplink address or on-link gateway"));
        }
        Ok(uplink)
    }

    fn netmask(self) -> u32 {
        u32::MAX << (32 - self.prefix)
    }

    pub(crate) fn on_link(self, ip: Ipv4Addr) -> bool {
        let mask = self.netmask();
        u32::from(ip) & mask == u32::from(self.address) & mask
    }

    pub(crate) fn usable(self, ip: Ipv4Addr) -> bool {
        let mask = self.netmask();
        let host = u32::from(ip) & !mask;
        self.prefix >= 31 || (host != 0 && host != !mask)
    }
}

fn hardware_field(value: &str, pattern: &[u8]) -> bool {
    value.len() == pattern.len()
        && value
            .bytes()
            .zip(pattern)
            .all(|(byte, pattern)| match pattern {
                b'h' => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
                b'f' => (b'0'..=b'7').contains(&byte),
                other => byte == *other,
            })
}

pub fn management_rule(
    profile: Option<&Profile<'_>>,
    listen: Option<SocketAddr>,
) -> io::Result<Option<(Ipv4Addr, u16)>> {
    match (
        profile,
        listen.filter(|address| !address.ip().is_loopback()),
    ) {
        (profile, None) if profile.is_none_or(|profile| profile.operator.is_none()) => Ok(None),
        (Some(profile), Some(SocketAddr::V4(listen))) if profile.uplink.address == *listen.ip() => {
            profile
                .operator
                .map(|peer| Some((peer, listen.port())))
                .ok_or_else(|| invalid("an uplink listener needs an enrolled management peer"))
        }
        _ => Err(invalid(
            "the management listener must match the signed Host uplink profile",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uplink_requires_exact_listener_and_single_signed_binding() -> io::Result<()> {
        let record = "FVCA-HOST-NETWORK-1\npci=0000:06:00.0\nmac=02:fc:00:00:00:01\naddress=192.168.44.15/24\ngateway=192.168.44.1\noperator=192.168.44.20\n";
        let profile = Profile::parse(record)?;
        let listener = Some("192.168.44.15:9443".parse().unwrap());
        assert_eq!(
            management_rule(Some(&profile), listener)?,
            Some((Ipv4Addr::new(192, 168, 44, 20), 9443))
        );
        assert!(management_rule(None, listener).is_err());
        assert!(management_rule(Some(&profile), None).is_err());
        assert!(
            management_rule(Some(&profile), Some("192.168.44.16:9443".parse().unwrap())).is_err()
        );
        assert!(Profile::parse(&record.replace("192.168.44.1\n", "192.168.45.1\n")).is_err());
        assert!(Profile::parse(&record.replace("02:fc:", "01:fc:")).is_err());
        let argument = format!("{ARGUMENT}={}", "c".repeat(64));
        assert!(binding(&argument)?.is_some());
        assert!(binding(&format!("{argument} {argument}")).is_err());
        Ok(())
    }
}
