#!/usr/bin/env python3
"""Exercise one-shot UEFI selection and candidate health on disposable 4Kn slots."""

import argparse
import json
from pathlib import Path
import re
import runpy
import struct
import subprocess
from types import SimpleNamespace
from uuid import UUID

from virt.firmware.efi.efivar import EfiVar
from virt.firmware.varstore.edk2 import Edk2VarStore


STABLE = 0x000a
CANDIDATE = 0x000b
SECTOR = 4096


def esp(image):
    table = json.loads(subprocess.check_output(["sfdisk", "--json", "--sector-size", str(SECTOR), image]))
    matches = [(number, part) for number, part in enumerate(table["partitiontable"]["partitions"], 1)
               if part["name"] == "fvca-esp"]
    if len(matches) != 1:
        raise ValueError(f"expected exactly one FVCA ESP in {image}")
    return matches[0]


def load_option(number, part, description):
    device = struct.pack("<BBHIQQ16sBB", 4, 1, 42, number, part["start"], part["size"],
                         UUID(part["uuid"]).bytes_le, 2, 2)
    filename = "\\EFI\\BOOT\\BOOTX64.EFI\0".encode("utf-16-le")
    path = device + struct.pack("<BBH", 4, 4, 4 + len(filename)) + filename + b"\x7f\xff\x04\x00"
    return struct.pack("<IH", 1, len(path)) + (description + "\0").encode("utf-16-le") + path


def prepare_vars(source, destination, stable, candidate, *, next_id=None):
    store = Edk2VarStore(source)
    variables = store.get_varlist()
    for name in tuple(variables):
        if name in ("BootNext", "BootOrder") or (len(name) == 8 and name.startswith("Boot")):
            del variables[name]
    values = {
        "BootOrder": struct.pack("<HH", STABLE, CANDIDATE),
        f"Boot{STABLE:04X}": load_option(*stable, "FVCA stable"),
        f"Boot{CANDIDATE:04X}": load_option(*candidate, "FVCA candidate"),
    }
    for name, value in values.items():
        variables[name] = EfiVar(name, attr=7, data=value)
    if next_id is not None:
        variables.set_boot_next(next_id)
    store.write_varstore(destination, variables)


def qualify(args):
    lab = runpy.run_path(Path(__file__).with_name("check-storage.py"))
    stable, candidate = esp(args.stable), esp(args.candidate)
    args.output.mkdir(mode=0o700)
    variables = args.output / "trial-vars.fd"
    password = (args.lab / "storage.key").read_bytes()

    def mirror(label):
        members = []
        for side in ("a", "b"):
            source = args.lab / f"member-{side}.raw"
            member = args.output / f"{label}-member-{side}.raw"
            subprocess.run(["cp", "--reflink=auto", "--sparse=always", "--", source, member], check=True)
            members.append(member)
        return members

    def run(name, selected, companion, marker, members, *, finish=None, required=(), forbidden=(), refusal=False):
        options = SimpleNamespace(guest=False, disk=args.stable, runtime=companion, variables=variables,
                                  output=args.output, nvme_boot=True, boot_sector_size=SECTOR, persistent_boot=True,
                                  memory_mib=4096)
        finish = finish or lab["READY"]
        before = Edk2VarStore(variables).get_varlist().get("BootNext")
        for attempt in range(1, 4):
            transcript = name if attempt == 1 else f"{name}-retry-{attempt - 1}"
            prompts, log = lab["boot"](options, transcript, password, *members, ready_marker=finish,
                                       timeout=135, firmware_timeout=40)
            if b"Kernel command line:" in log:
                break
            after = Edk2VarStore(variables).get_varlist().get("BootNext")
            if (before.data if before else None) != (after.data if after else None):
                # Do not retry if the firmware already consumed the override.
                break
        selected = f"FVCA_HYPERVISOR_SLOT_VERIFIED {selected[1]['uuid'].lower()}".encode()
        expected = (b"Secure boot enabled", b"FVCA_SELINUX_ENFORCING", selected, lab["HOST_PROFILES"], finish, marker, *required)
        if (prompts != 2 or (not refusal and lab["FAIL"] in log) or not all(value in log for value in expected)
                or any(value in log for value in forbidden)):
            raise ValueError(f"{name} did not reach the expected Secure Boot, Btrfs and trial state. See {transcript}.log")
        print(f"{name} passed", flush=True)
        return log

    def state(next_id=None, order=None):
        values = Edk2VarStore(variables).get_varlist()
        current = values["BootOrder"].data
        if current[:4] != struct.pack("<HH", STABLE, CANDIDATE) or (order is not None and current != order):
            raise ValueError("unexpected persistent EFI BootOrder")
        override = values.get("BootNext")
        if (override.data if override else None) != (struct.pack("<H", next_id) if next_id is not None else None):
            raise ValueError("unexpected persistent EFI BootNext")
        return current

    tx = str(args.transaction).encode()
    armed = b"FVCA_TRIAL_ARMED " + tx + f" {CANDIDATE:04x}".encode()
    started = b"FVCA_TRIAL_CANDIDATE_STARTED " + tx
    healthy = b"FVCA_TRIAL_HEALTH_RECORDED " + tx
    available = b"FVCA_TRIAL_HEALTH_AVAILABLE " + tx
    prior = b"FVCA_TRIAL_PREVIOUSLY_RECORDED " + tx

    prepare_vars(args.variables, variables, stable, candidate)
    members = mirror("trial")
    run("trial-armed-from-stable", stable, args.candidate, armed, members)
    order = state(CANDIDATE)
    log = run("candidate-health-recorded", candidate, args.candidate, started, members, finish=healthy,
              required=(lab["READY"], b"FVCA_SERVICE_GUEST_READY", b"FVCA_LIBVIRT_LIFECYCLE_OK"))
    boot_id = re.search(re.escape(started) + rb" ([0-9a-f-]{36})", log)
    runtime = re.search(rb"FVCA_VM_RUNTIME_ACTIVE ([0-9a-f]{64})", log)
    if boot_id is None or runtime is None:
        raise ValueError("candidate health log lacks its boot and runtime identities")
    state(order=order)
    run("stable-read-back-health", stable, args.candidate, prior, members,
        required=(b" ".join((available, boot_id[1], runtime[1])),), forbidden=(armed,))
    state(order=order)

    variables = args.output / "interruption-vars.fd"
    prepare_vars(args.variables, variables, stable, candidate)
    members = mirror("interruption")
    run("interrupted-trial-armed", stable, args.candidate, armed, members)
    order = state(CANDIDATE)
    run("cut-power-before-health", candidate, args.candidate, started, members, finish=started,
        forbidden=(healthy,))
    state(order=order)
    run("stable-resumed-without-health", stable, args.candidate, prior, members,
        forbidden=(available, armed))
    state(order=order)

    changed = args.output / "changed-candidate.raw"
    subprocess.run(["cp", "--reflink=auto", "--sparse=always", "--", args.candidate, changed], check=True)
    part = candidate[1]
    with changed.open("r+b") as disk:
        disk.seek((part["start"] + part["size"]) * SECTOR - 1)
        value = disk.read(1)[0]
        disk.seek(-1, 1)
        disk.write(bytes([value ^ 1]))
    variables = args.output / "refusal-vars.fd"
    prepare_vars(args.variables, variables, stable, candidate)
    run("changed-candidate-refused", stable, changed,
        b"FVCA_TRIAL_REFUSED candidate ESP differs from the approved image", mirror("refusal"))
    state()

    variables = args.output / "unarmed-vars.fd"
    prepare_vars(args.variables, variables, stable, candidate, next_id=CANDIDATE)
    denied = b"candidate trial has no recorded stable authorization"
    run("unarmed-candidate-refused", candidate, args.candidate, denied, mirror("unarmed"), finish=denied,
        forbidden=(started, b"FVCA_SERVICE_GUEST_READY", healthy), refusal=True)
    state()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("stable", "candidate", "variables", "lab", "output"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--transaction", type=UUID, required=True)
    qualify(parser.parse_args())


if __name__ == "__main__":
    main()
