//! Host authorization for the registered Guest's separate workload uplink.

use std::io;

use crate::host_network::{Nic, Uplink, field, valid_mac};
use crate::workload_network;
use crate::{digest, invalid, signed_argument};

pub const ARGUMENT: &str = "fvca.host_workload";
pub const RECORD: &str = "host-workload";
pub const GUEST_RECORD: &str = "host-workload-guest";
pub const SUPPORT: &str = "host-workload-network-v2";
pub const GUEST_PCI: &str = "0000:00:06.0";
pub const LIMIT: usize = 256;

pub fn binding(cmdline: &str) -> io::Result<Option<&str>> {
    signed_argument(cmdline, ARGUMENT)?
        .map(|value| digest(value, ""))
        .transpose()
}

pub struct Enrollment<'a> {
    pub port: Nic<'a>,
    pub guest: &'a str,
}

impl<'a> Enrollment<'a> {
    pub fn parse(raw: &'a str) -> io::Result<Self> {
        if raw.len() > LIMIT {
            return Err(invalid(
                "the Host workload enrollment exceeds its size bound",
            ));
        }
        let lines: Vec<_> = raw.split('\n').collect();
        let ["FVCA-HOST-WORKLOAD-1", pci, mac, guest, ""] = lines.as_slice() else {
            return Err(invalid("expected the canonical Host workload enrollment"));
        };
        Ok(Self {
            port: Nic::parse(pci, mac)?,
            guest: digest(field(guest, "guest=")?, "")?,
        })
    }

    pub fn validate(
        &self,
        guest: &workload_network::Profile<'_>,
        management: Option<Uplink<'_>>,
    ) -> io::Result<()> {
        let uplink = guest.uplink;
        if uplink.pci != GUEST_PCI || uplink.mac == self.port.mac {
            return Err(invalid(
                "the Guest NIC must use the registered slot and a distinct MAC",
            ));
        }
        if let Some(management) = management
            && (self.port.pci == management.pci
                || self.port.mac == management.mac
                || uplink.mac == management.mac
                || uplink.on_link(management.address)
                || management.on_link(uplink.address)
                || guest
                    .ingress
                    .iter()
                    .chain(&guest.egress)
                    .map(|&(_, address, _)| address)
                    .any(|address| management.on_link(address)))
        {
            return Err(invalid(
                "the workload uplink intersects the signed management LAN",
            ));
        }
        Ok(())
    }
}

pub fn require_guest(authorized: Option<&str>, guest_cmdline: &str) -> io::Result<()> {
    if workload_network::binding(guest_cmdline)? != authorized {
        return Err(invalid(
            "the Guest workload network differs from Host enrollment",
        ));
    }
    Ok(())
}

pub fn ready_mac<'a>(
    record: &'a str,
    host_digest: &str,
    guest_cmdline: &str,
) -> io::Result<&'a str> {
    let lines: Vec<_> = record.split('\n').collect();
    let ["FVCA-HOST-WORKLOAD-READY-1", host, guest, mac, ""] = lines.as_slice() else {
        return Err(invalid("invalid active Host workload enrollment"));
    };
    let mac = field(mac, "mac=")?;
    if digest(field(host, "host=")?, "")? != host_digest || !valid_mac(mac) {
        return Err(invalid(
            "the active Host workload bridge differs from signed boot",
        ));
    }
    require_guest(Some(digest(field(guest, "guest=")?, "")?), guest_cmdline)?;
    Ok(mac)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bindings_reject_omission_replacement_and_duplicate() -> io::Result<()> {
        let host = "a".repeat(64);
        let guest = "b".repeat(64);
        let ready = format!(
            "FVCA-HOST-WORKLOAD-READY-1\nhost={host}\nguest={guest}\nmac=52:54:00:10:20:30\n"
        );
        let cmdline = format!("{}={guest}", workload_network::ARGUMENT);
        assert_eq!(ready_mac(&ready, &host, &cmdline)?, "52:54:00:10:20:30");
        assert!(ready_mac(&ready, &host, "").is_err());
        assert!(ready_mac(&ready, &guest, &cmdline).is_err());
        assert!(ready_mac(&ready, &host, &format!("{cmdline} {cmdline}")).is_err());
        assert!(require_guest(None, &cmdline).is_err());
        Ok(())
    }
}
