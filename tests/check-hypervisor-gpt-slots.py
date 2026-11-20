#!/usr/bin/env python3
"""Check independent Secure Boot Hypervisor GPT slots on disposable QEMU disks."""

import argparse
import json
from pathlib import Path
import runpy
import subprocess
from types import SimpleNamespace


HOST_DATA = "fvca-host_data"


def layout(disk, sector):
    table = json.loads(subprocess.check_output(["sfdisk", "--json", "--sector-size", str(sector), disk]))["partitiontable"]
    parts = {entry["name"]: (number, entry["uuid"].lower())
             for number, entry in enumerate(table["partitions"], start=1)}
    expected = {f"fvca-{member}" for member in ("esp", "core", "core_verity", "runtime",
                                                "runtime_verity", "guest", "guest_verity")}
    if (table["label"] != "gpt" or table["sectorsize"] != sector or len(table["partitions"]) != len(parts)
            or not expected <= parts.keys() <= expected | {HOST_DATA}):
        raise ValueError(f"unexpected Hypervisor slot layout in {disk.name}")
    return table["id"].lower(), parts


def qualify(args):
    lab = runpy.run_path(Path(__file__).with_name("check-storage.py"))
    boot = lab["boot"]
    disk_a, parts_a = layout(args.first, args.sector_size)
    disk_b, parts_b = layout(args.second, args.sector_size)
    if disk_a == disk_b or len({part[1] for part in (*parts_a.values(), *parts_b.values())}) != len(parts_a) + len(parts_b):
        raise ValueError("the two provisioned slots must have distinct disk and partition UUIDs")
    integrated = HOST_DATA in parts_a
    if integrated != (HOST_DATA in parts_b):
        raise ValueError("both slots must use the same Host data layout")
    args.output.mkdir(mode=0o700)
    password = (args.lab / "storage.key").read_bytes()
    members = [] if integrated else [args.lab / f"member-{side}.raw" for side in ("a", "b")]

    def run(name, selected, other, *, denied=None, storage_denial=False):
        options = SimpleNamespace(guest=False, disk=selected, runtime=other, variables=args.variables,
                                  output=args.output, nvme_boot=not args.virtio, boot_sector_size=args.sector_size,
                                  memory_mib=4096 if integrated else 2048, no_default_devices=integrated)
        ready = denied or lab["READY"]
        for attempt in range(1, 4):
            prompts, log = boot(options, f"{name}-{attempt}", None if denied else password, *members,
                                firmware=args.firmware or lab["OVMF_CODE"],
                                timeout=135 if integrated else 55, firmware_timeout=36, ready_marker=ready)
            if b"Kernel command line:" in log:
                break
        log = lab["KERNEL_MOUNT_NOTICE"].sub(b"", lab["KERNEL_AUDIT"].sub(b"", log))
        esp = layout(selected, args.sector_size)[1]["fvca-esp"][1]
        slot_marker = f"FVCA_HYPERVISOR_SLOT_VERIFIED {esp}".encode()
        if denied is not None:
            if (denied not in log or lab["READY"] in log or prompts
                    or (storage_denial and slot_marker not in log)):
                raise ValueError(f"{name} did not refuse the unsafe slot before storage unlock")
        else:
            expected = (slot_marker, b"Secure boot enabled", b"FVCA_SELINUX_ENFORCING",
                        b"FVCA_VM_RUNTIME_ACTIVE", lab["HOST_PROFILES"], lab["READY"])
            if integrated:
                expected += (lab["HOST_AUTHENTICATED"], b"FVCA_SERVICE_GUEST_READY")
            if prompts != 2 or lab["FAIL"] in log or not all(marker in log for marker in expected):
                raise ValueError(f"{name} did not boot the selected signed tuple and Btrfs mirror")
        print(f"{name} passed", flush=True)

    if integrated:
        missing = b"both authorized storage members are required"
        run("first-without-companion", args.first, None, denied=missing, storage_denial=True)
        run("second-without-companion", args.second, None, denied=missing, storage_denial=True)
    else:
        run("single-slot", args.first, None)
    run("first-selected", args.first, args.second)
    run("second-selected", args.second, args.first)

    split = []
    for side, source, current, other in (("a", args.first, parts_a, parts_b), ("b", args.second, parts_b, parts_a)):
        copy = args.output / f"mixed-{side}.raw"
        subprocess.run(["cp", "--reflink=auto", "--sparse=always", "--", source, copy], check=True)
        subprocess.run(["sfdisk", "--sector-size", str(args.sector_size), "--part-uuid",
                        copy, str(current["fvca-runtime"][0]), other["fvca-runtime"][1]],
                       check=True, capture_output=True)
        split.append(copy)
    run("split-slot-rejected", *split, denied=b"Hypervisor slot partitions must reside on one GPT disk")
    run("duplicate-slot-rejected", args.first, split[1], denied=b"more than one device has the authorized partition UUID")
    if integrated:
        duplicate = args.output / "duplicate-host-data.raw"
        subprocess.run(["cp", "--reflink=auto", "--sparse=always", "--", args.second, duplicate], check=True)
        subprocess.run(["sfdisk", "--sector-size", str(args.sector_size), "--part-uuid",
                        duplicate, str(parts_b[HOST_DATA][0]), parts_a[HOST_DATA][1]],
                       check=True, capture_output=True)
        run("duplicate-host-data-rejected", args.first, duplicate,
            denied=b"more than one device has the authorized partition UUID", storage_denial=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("first", "second", "variables", "lab", "output"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--virtio", action="store_true", help="exercise the same layout over virtio-blk in the lab")
    parser.add_argument("--firmware", type=Path, help="alternative Secure Boot firmware matching the supplied variables")
    parser.add_argument("--sector-size", type=int, choices=(512, 4096), default=4096)
    qualify(parser.parse_args())


if __name__ == "__main__":
    main()
