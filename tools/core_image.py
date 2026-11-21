"""Verify the Secure Boot UKI and root selection in FVCA core images."""

import json
import re

from image_verity import read_layout, verify_verity
from runtime_boot import BASE_ROOT_OPTIONS, BOOT_EFI, DIRECT_ROOT_OPTIONS, PARTITIONS, SECURE_KERNEL_OPTIONS, run


def inspect_uki(uki, certificate):
    run("sbverify", "--cert", certificate, uki)
    sections = json.loads(run("ukify", "--json=short", "inspect", uki, capture_output=True).stdout)
    if sections.get("_profiles"):
        raise ValueError("unexpected UKI profiles")
    return sections


def extract_uki_section(uki, section, destination):
    run("ukify", f"--section=.{section}:binary@{destination}", "inspect", uki, capture_output=True)


def verify_command_line(cmdline, root_options, *, hardened=False, devices=None):
    options = {
        "dm_verity.require_signatures": "1",
        "enforcing": "1",
        "proc_mem.force_override": "never",
        "systemd.restrict_filesystem_access": "exec",
        "systemd.verity_root_options": root_options,
    }
    if hardened:
        options.update(option.split("=", 1) for option in SECURE_KERNEL_OPTIONS)
    if devices:
        options.update(devices)
    arguments = [arg.partition("=") for arg in cmdline.split()]
    for option, expected in options.items():
        values = [value for name, _, value in arguments if name == option]
        if values != [expected]:
            raise ValueError(f"the signed UKI must specify exactly one {option}={expected}")
    hashes = [value for name, _, value in arguments if name == "roothash"]
    if len(hashes) != 1 or re.fullmatch(r"[0-9a-f]{64}", hashes[0]) is None:
        raise ValueError("the signed UKI must specify one SHA-256 root hash")
    return hashes[0]


def verify(image, boot_certificate, verity_certificate, work, *, direct_boot=False):
    sector_size, partitions = read_layout(image, PARTITIONS)
    uki = work / "boot.efi"
    esp_offset = partitions["esp"]["start"] * sector_size
    run("mcopy", "-i", f"{image}@@{esp_offset}", BOOT_EFI, uki)
    sections = inspect_uki(uki, boot_certificate)
    root_options = DIRECT_ROOT_OPTIONS if direct_boot else BASE_ROOT_OPTIONS
    expected_root = verify_command_line(sections[".cmdline"]["text"], root_options, hardened=direct_boot)
    root_hash = verify_verity(image, sector_size, partitions, verity_certificate, work, expected_root)
    print(f"Verified UKI execution policy, DDI signature and dm-verity data for {root_hash}")
    return root_hash
