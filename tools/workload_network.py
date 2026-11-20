"""Validate the canonical Service Guest workload uplink before signing."""

import ipaddress
import re

from runtime_boot import WORKLOAD_NETWORK_ARGUMENT, WORKLOAD_NETWORK_POLICY
from workload_oci import read_bytes, sha256


PRIVATE = tuple(map(ipaddress.IPv4Network, ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")))


def ipv4(raw):
    address = ipaddress.IPv4Address(raw)
    if str(address) != raw or address.packed[0] in (0, 127) or address.packed[0] >= 224 or address.is_link_local:
        raise ValueError("expected a canonical unicast IPv4 address")
    return address


def parse(data):
    base = re.match(
        r"FVCA-GUEST-WORKLOAD-NETWORK-1\npci=([0-9a-f]{4}:[0-9a-f]{2}:[01][0-9a-f]\.[0-7])\n"
        r"mac=((?:[0-9a-f]{2}:){5}[0-9a-f]{2})\naddress=([0-9./]+)\n"
        r"gateway=([0-9.]+|none)\nmtu=([1-9][0-9]{3})\ndns=([0-9.]+|none)\n", data)
    if not base or int(base[2][:2], 16) & 1 or base[2] == "00:00:00:00:00:00":
        raise ValueError("invalid canonical workload uplink")
    local = ipaddress.IPv4Interface(base[3])
    if str(local) != base[3] or not local.network.prefixlen or not any(local.ip in subnet for subnet in PRIVATE):
        raise ValueError("the workload uplink requires a canonical private IPv4 subnet")

    def usable(address):
        return local.network.prefixlen >= 31 or address not in (local.network.network_address, local.network.broadcast_address)

    gateway = None if base[4] == "none" else ipv4(base[4])
    if (not usable(local.ip) or not 1280 <= int(base[5]) <= 1500
            or gateway is not None and (gateway == local.ip or gateway not in local.network or not usable(gateway))):
        raise ValueError("invalid workload address, on-link gateway or MTU")

    endpoints = set()

    def peer(raw):
        address = ipv4(raw)
        if address == local.ip or not (usable(address) if address in local.network else gateway is not None):
            raise ValueError("workload peer has no route through the signed uplink")
        endpoints.add(address)

    if base[6] != "none":
        peer(base[6])
    rules = data[base.end():]
    if rules and not rules.endswith("\n"):
        raise ValueError("the workload network record needs a final newline")
    seen = {"ingress": set(), "egress": set()}
    for line in rules.removesuffix("\n").split("\n") if rules else ():
        rule = re.fullmatch(r"(ingress|egress)=(tcp|udp),([0-9.]+),([1-9][0-9]{0,4})", line)
        if rule is None or int(rule[4]) > 65535 or len(seen[rule[1]]) == 32 or line in seen[rule[1]]:
            raise ValueError("invalid or duplicate workload peer rule")
        peer(rule[3])
        seen[rule[1]].add(line)
    return base[1], base[2], local, endpoints


def selection(path, trust, cmdline):
    if any(word.partition("=")[0] == WORKLOAD_NETWORK_ARGUMENT for word in cmdline.split()):
        raise ValueError("the shared core already configures a workload uplink")
    if path is None:
        return (), ()
    if not trust:
        raise ValueError("a workload uplink requires signed workload trust")
    raw = read_bytes(path, 4096)
    data = raw.decode("ascii")
    if "\r" in data:
        raise ValueError("the workload network record requires Unix line endings")
    parse(data)
    digest = sha256(raw).removeprefix("sha256:")
    return ((WORKLOAD_NETWORK_POLICY, raw),), (f"{WORKLOAD_NETWORK_ARGUMENT}={digest}",)
