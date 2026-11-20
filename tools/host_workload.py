"""Enroll an independent Host workload port and an exact Guest network record."""

import hashlib
import ipaddress
import re

from runtime_boot import (
    HOST_WORKLOAD_ARGUMENT, HOST_WORKLOAD_GUEST, HOST_WORKLOAD_POLICY, WORKLOAD_NETWORK_ARGUMENT,
)
from workload_oci import read_bytes
import workload_network


def selection(path, guest_cmdline, management):
    guest_markers = [word for word in guest_cmdline.split()
                     if word.partition("=")[0] == WORKLOAD_NETWORK_ARGUMENT]
    if path is None:
        if guest_markers:
            raise ValueError("a connected Service Guest requires a signed Host workload uplink")
        return (), ()
    raw = read_bytes(path, 4352)
    port = re.match(rb"FVCA-HOST-WORKLOAD-1\npci=([0-9a-f]{4}:[0-9a-f]{2}:[01][0-9a-f]\.[0-7])\n"
                    rb"mac=((?:[0-9a-f]{2}:){5}[0-9a-f]{2})\n", raw)
    if port is None or int(port[2][:2], 16) & 1 or port[2] == b"00:00:00:00:00:00":
        raise ValueError("invalid Host workload port identity")
    site_pci, site_mac = (value.decode("ascii") for value in port.groups())
    guest = raw[port.end():]
    if len(guest) > 4096 or b"\r" in guest:
        raise ValueError("invalid Host-enrolled Guest workload record")
    pci, mac, local, peers = workload_network.parse(guest.decode("ascii"))
    if pci != "0000:00:06.0" or mac == site_mac:
        raise ValueError("the Guest requires its registered PCI slot and a distinct MAC")
    digest = hashlib.sha256(guest).hexdigest()
    if guest_markers != [f"{WORKLOAD_NETWORK_ARGUMENT}={digest}"]:
        raise ValueError("the registered Guest boot differs from the enrolled workload network")
    if management:
        fields = dict(line.split("=", 1) for line in management[0][1].decode("ascii").splitlines()[1:])
        lan = ipaddress.IPv4Interface(fields["address"]).network
        if (fields["pci"] == site_pci or fields["mac"] in (site_mac, mac)
                or lan.overlaps(local.network) or any(peer in lan for peer in peers)):
            raise ValueError("the workload uplink intersects the signed management LAN")
    site = raw[:port.end()] + f"guest={digest}\n".encode("ascii")
    return ((HOST_WORKLOAD_POLICY, site), (HOST_WORKLOAD_GUEST, guest)), (
        f"{HOST_WORKLOAD_ARGUMENT}={hashlib.sha256(site).hexdigest()}",
    )
