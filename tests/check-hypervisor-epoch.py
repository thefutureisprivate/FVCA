#!/usr/bin/env python3
"""Boot signed GPT slots against disposable copies of an enrolled software TPM."""

import argparse
from contextlib import nullcontext
import importlib.util
from pathlib import Path
import re
import runpy


spec = importlib.util.spec_from_file_location("check_storage", Path(__file__).with_name("check-storage.py"))
storage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(storage)

ACCEPTED = b"FVCA_HYPERVISOR_EPOCH_ACCEPTED"
REFUSED = b"FVCA_HYPERVISOR_EPOCH_REFUSED"
UNLOCKED = b"FVCA_HOST_STORAGE_TPM_UNLOCKED"


def qualify(args):
    gpt = runpy.run_path(Path(__file__).with_name("check-hypervisor-gpt-slots.py"))
    pin = args.pin_file.read_bytes().strip()
    if re.fullmatch(b"[0-9a-f]{24}", pin) is None:
        raise ValueError("expected a randomly generated 24-hex-character lab PIN")
    first, second = (int.from_bytes((args.states / f"floor-{name}").read_bytes(), "big")
                     for name in ("one", "two"))
    if first == 0 or second != first + 1:
        raise ValueError("expected two successive TPM floor values")
    members = [args.lab / f"member-{label}.raw" for label in ("a", "b")]
    args.output.mkdir(mode=0o700)
    args.guest = False
    args.nvme_boot = True
    args.no_default_devices = True
    args.boot_sector_size = 4096
    args.memory_mib = 4096
    cases = [
        ("initially-eligible", args.older, None, args.states / "counter-one", first, first, None),
        ("replayed-slot", args.older, None, args.states / "counter-two", first, second, b"below the TPM floor"),
        ("eligible-recovery", args.eligible, None, args.states / "counter-two", second, second, None),
        ("wrong-policy", args.wrong_policy, None, args.states / "counter-two", second, second, b"policy differ"),
        ("uninitialized-counter", args.eligible, None, args.states / "uninitialized", second, 0, b"policy differ"),
        ("missing-counter", args.eligible, None, args.original_tpm, second, 0, b"TPM refused the enrolled release counter"),
        ("missing-tpm", args.eligible, None, None, second, 0, b"TPM resource manager device is required"),
    ]
    if args.paired_slots is not None:
        a, b = args.paired_slots
        for phase, floor, state in (("initial-floor", first, "counter-one"), ("raised-floor", second, "counter-two")):
            cases.extend((f"paired-slot-{name}-{phase}", disk, peer, args.states / state, second, floor, None)
                         for name, disk, peer in (("a", a, b), ("b", b, a)))
    for name, disk, peer, state, epoch, floor, reason in cases:
        args.disk = disk
        args.runtime = peer
        _, parts = gpt["layout"](disk, args.boot_sector_size)
        esp = f"FVCA_HYPERVISOR_SLOT_VERIFIED {parts['fvca-esp'][1]}".encode("ascii")
        for attempt in range(1, 4):
            emulator = nullcontext(None) if state is None else storage.software_tpm(state)
            with emulator as socket:
                prompts, output = storage.boot(
                    args, f"{name}-{attempt}", pin if reason is None else None, *(members if peer is None else ()),
                    firmware=args.firmware, tpm_socket=socket, firmware_timeout=30, timeout=105,
                    ready_marker=UNLOCKED if reason is None else storage.FAIL,
                )
            if b"Kernel command line:" in output:
                break
        output = storage.rejoin_serial_output(output)
        if (b"secureboot: Secure boot enabled" not in output or b"FVCA_SELINUX_ENFORCING" not in output or esp not in output
                or b"passphrase for disk" in output):
            raise ValueError(f"{name} did not reach the gate through the verified slot")
        prompt = storage.PROMPT.search(output)
        if reason is None:
            marker = ACCEPTED + f" {epoch} {floor}".encode("ascii")
            required = (marker, storage.HOST_AUTHENTICATED, storage.HOST_PROFILES, UNLOCKED)
            if (prompts != 2 or prompt is None or storage.FAIL in output
                    or not all(mark in output for mark in required) or output.find(marker) >= prompt.start()):
                raise ValueError(f"{name} did not check the epoch before unlocking authenticated Btrfs")
        else:
            if (prompts or prompt is not None or REFUSED not in output or reason not in output
                    or storage.FAIL not in output or any(mark in output for mark in (
                        ACCEPTED, UNLOCKED, storage.ACTIVE, storage.HOST_AUTHENTICATED,
                        storage.HOST_PROFILES, b"FVCA_VM_RUNTIME_ACTIVE", b"FVCA_SERVICE_GUEST_READY",
                    ))):
                raise ValueError(f"{name} did not fail closed before asking for the Host PIN")
        print(f"{name} passed", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("older", "eligible", "wrong-policy", "lab", "states", "original-tpm", "pin-file",
                 "variables", "firmware", "output"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--paired-slots", nargs=2, type=Path, metavar=("A", "B"),
                        help="also boot both provisioned slots at each floor using their integrated Host members")
    qualify(parser.parse_args())
