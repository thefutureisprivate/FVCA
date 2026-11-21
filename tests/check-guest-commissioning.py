#!/usr/bin/env python3
"""Boot the signed Host and verify initial Service Guest commissioning in nested KVM."""

import argparse
from pathlib import Path
import re
import runpy
import subprocess
import tempfile
from types import SimpleNamespace


COMMISSIONED = b"FVCA_GUEST_DATA_COMMISSIONED "
REJECTED = b"the Guest disk does not match the signed commissioning seed"
GUEST_READY = b"FVCA_SERVICE_GUEST_READY"


def qualify(args):
    tests = Path(__file__).parent
    storage = runpy.run_path(str(tests / "check-storage.py"))
    gpt = runpy.run_path(str(tests / "check-hypervisor-gpt-slots.py"))
    _, parts = gpt["layout"](args.disk, 4096)
    slot = f"FVCA_HYPERVISOR_SLOT_VERIFIED {parts['fvca-esp'][1]}".encode()
    required = (b"secureboot: Secure boot enabled", b"FVCA_SELINUX_ENFORCING",
                storage["HOST_AUTHENTICATED"], slot)
    args.output.mkdir(mode=0o700)
    options = SimpleNamespace(disk=args.disk, runtime=None, output=args.output, variables=args.variables,
                              guest=False, nvme_boot=True, boot_sector_size=4096, no_default_devices=True,
                              memory_mib=8192, vcpus=4)

    def boot(name, lab, members, marker):
        password = (lab / "storage.key").read_bytes()
        if re.fullmatch(b"[0-9a-f]{64}", password) is None:
            raise ValueError("unexpected disposable storage credential encoding")
        for attempt in range(1, 4):
            prompts, log = storage["boot"](options, f"{name}-{attempt}", password, *members, ready_marker=marker,
                                          firmware_timeout=30, timeout=150)
            if b"Kernel command line:" in log:
                break
        log = storage["rejoin_serial_output"](log)
        if prompts != 2 or any(marker not in log for marker in required):
            raise ValueError(f"{name} did not reach the authenticated Secure Boot storage boundary")
        return log

    def members(lab):
        return tuple(lab / f"member-{side}.raw" for side in ("a", "b"))

    with tempfile.TemporaryDirectory(prefix="mirror-", dir=args.output) as directory:
        writable = members(Path(directory))
        for source, target in zip(members(args.lab), writable, strict=True):
            subprocess.run(["cp", "--reflink=auto", "--sparse=always", "--", source, target], check=True)
        options.persistent_members = True
        first = boot("initial", args.lab, writable, storage["READY"])
        storage["require_nested_guest_ready"](first, required, expected_launches=1)
        if first.count(COMMISSIONED) != 1 or not 0 <= first.find(COMMISSIONED) < first.find(GUEST_READY):
            raise ValueError("the initial Guest became ready without exactly one prior commissioning")
        print("initial signed commissioning and nested Guest readiness passed", flush=True)

        again = boot("cold-start", args.lab, writable, storage["READY"])
        storage["require_nested_guest_ready"](again, required, expected_launches=1)
        if COMMISSIONED in again:
            raise ValueError("a cold start commissioned a second Guest volume")
        print("cold start reused the installed Guest disk", flush=True)

    options.persistent_members = False
    rejected = boot("altered-seed", args.altered_lab, members(args.altered_lab), storage["FAIL"])
    if (REJECTED not in rejected or storage["FAIL"] not in rejected
            or any(marker in rejected for marker in (COMMISSIONED, GUEST_READY, storage["READY"]))
            or re.search(rb"launch-guest\[[0-9]+\]: FVCA_KVM_GUEST_CONFINED", rejected)):
        raise ValueError("the Hypervisor did not fail before launching a Guest with an altered seed")
    print("altered seed was rejected before Guest launch", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("disk", "variables", "lab", "altered-lab", "output"):
        parser.add_argument(f"--{option}", type=lambda path: Path(path).absolute(), required=True)
    try:
        qualify(parser.parse_args())
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Guest commissioning qualification failed: {error}\n")


if __name__ == "__main__":
    main()
