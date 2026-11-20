#!/usr/bin/env python3
"""Qualify timeout and verified health on signed disposable KVM trial slots."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import runpy
import socket
import struct
import subprocess
import tempfile
import time
from types import SimpleNamespace


def qmp_events(path):
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(240)
        for _ in range(50):
            try:
                connection.connect(str(path))
                break
            except (FileNotFoundError, ConnectionRefusedError):
                time.sleep(0.1)
        else:
            raise ValueError("QEMU did not start its QMP server")
        with connection.makefile("rb") as messages:
            assert "QMP" in json.loads(messages.readline())
            connection.sendall(b'{"execute":"qmp_capabilities"}\n')
            return [event for line in messages if "event" in (event := json.loads(line))]


def authorize(args, binding, esp, selection, work):
    now = int(time.time())
    approval = work / "approval"
    approval.write_text(
        f"FVCA-HYPERVISOR-STANDING-TRIAL-2\nnot_before={now-60}\nexpires={now+1800}\n"
        f"stable_epoch=1\ncandidate_epoch=2\nepoch_policy_sha256={args.epoch_policy}\n"
        f"stable_core={args.core}\nstable_runtime={args.runtime}\nstable_guest_bundle={args.guest}\n"
        f"{binding}FVCA-HYPERVISOR-TRIAL-2\n{selection}{esp}"
        f"candidate_core={args.core}\ncandidate_runtime={args.runtime}\nguest_bundle={args.guest}\n",
        encoding="ascii",
    )
    signature = subprocess.check_output([
        "openssl", "pkeyutl", "-sign", "-rawin", "-inkey", args.sign_key, "-in", approval,
    ])
    return signature + approval.read_bytes()


def qualify(args):
    here = Path(__file__).parent
    storage = runpy.run_path(here / "check-storage.py")
    trial = runpy.run_path(here / "check-hypervisor-trial.py")
    standing = runpy.run_path(here / "check-hypervisor-standing-trial.py")
    stable = args.fixture / "stable.raw"
    selection = (args.fixture / "candidate.txt").read_text().split("\n", 1)[1]
    txn = selection.splitlines()[0].removeprefix("transaction=").encode()
    armed = b"FVCA_TRIAL_WATCHDOG_ARMED " + txn
    disarmed = b"FVCA_TRIAL_WATCHDOG_DISARMED " + txn
    healthy = b"FVCA_TRIAL_HEALTH_RECORDED " + txn
    guest_ready = b"FVCA_SERVICE_GUEST_READY"
    args.online_handoff = False
    for case, seconds, finish in (("expiry", 10, guest_ready), ("healthy", 180, healthy)):
        if args.case is not None and args.case != case:
            continue
        candidate = args.fixture / f"{case}.raw"
        stable_entry, candidate_entry = trial["esp"](stable), trial["esp"](candidate)
        variables = args.output / f"{case}-vars.fd"
        with tempfile.TemporaryDirectory(prefix="members-", dir=args.output) as path:
            work = Path(path)
            trial["prepare_vars"](args.variables, variables, stable_entry, candidate_entry)
            binding, esp = standing["candidate_fields"](candidate)
            envelope = authorize(args, binding, esp, selection, work)
            members = [work / f"member-{side}.raw" for side in ("a", "b")]
            for member in members:
                subprocess.run(["cp", "--reflink=auto", "--sparse=always", args.members / member.name, member], check=True)
            standing["install"](args, args.output / f"{case}-install.log", members, envelope, args.seed)
            for attempt in range(1, 4):
                with tempfile.TemporaryDirectory(prefix="fvca-qmp-") as directory, \
                        storage["software_tpm"](args.tpm_state) as tpm, ThreadPoolExecutor(max_workers=1) as worker:
                    qmp = Path(directory) / "qmp"
                    capture = worker.submit(qmp_events, qmp)
                    options = SimpleNamespace(disk=stable, runtime=candidate, guest=False, output=args.output,
                                              variables=variables, nvme_boot=True, persistent_boot=True,
                                              boot_sector_size=4096, no_default_devices=True, memory_mib=4096,
                                              trial_watchdog=True, qmp_path=qmp)
                    prompts, log = storage["boot"](
                        options, f"{case}-{attempt}", None, *members, firmware=args.firmware, tpm_socket=tpm,
                        firmware_timeout=35, timeout=235, ready_marker=finish, allow_reboot=True,
                    )
                    events = capture.result()
                if b"Kernel command line:" in log:
                    break
            (args.output / f"{case}-qmp.json").write_text(json.dumps(events, indent=2) + "\n")
        log = storage["rejoin_serial_output"](log)
        efi = trial["Edk2VarStore"](variables).get_varlist()
        assert efi.get("BootNext") is None
        assert efi["BootOrder"].data[:4] == struct.pack("<HH", trial["STABLE"], trial["CANDIDATE"])
        count = 3 if case == "expiry" else 1
        assert prompts == 0 and storage["FAIL"] not in log and finish in log and log.count(armed) == count
        boots = log.split(b"Linux version ")[1:]
        expected_boots = 7 if case == "expiry" else 2
        assert len(boots) == expected_boots and log.count(b"secureboot: Secure boot enabled") >= expected_boots
        for boot in boots:
            assert all(marker in boot for marker in (
                b"FVCA_SELINUX_ENFORCING", b"FVCA_HOST_STORAGE_UNLOCK_PROFILE tpm2-auto",
                b"FVCA_BTRFS_PROFILES raid1 raid1 raid1",
            ))
        for number in range(1, count + 1):
            stable_boot, candidate_boot = boots[2 * (number - 1):2 * number]
            standing["require_sequence"](stable_boot, (
                b"FVCA_HYPERVISOR_EPOCH_ACCEPTED 1 1", b"FVCA_TRIAL_ARMED " + txn + f" 000b {number}".encode(),
            ), args.output)
            standing["require_sequence"](candidate_boot, (
                armed + f" {seconds}".encode(), b"FVCA_HYPERVISOR_EPOCH_ACCEPTED 2 1",
                b"FVCA_TRIAL_CANDIDATE_STARTED " + txn,
            ), args.output)
        resets = [event["data"]["action"] for event in events if event["event"] == "WATCHDOG"]
        if case == "expiry":
            assert resets == ["reset"] * count
            assert disarmed not in log and healthy not in log
            assert all(guest_ready not in boot and b"reboot: Restarting system" not in boot for boot in boots[1::2])
            standing["require_sequence"](boots[-1], (
                b"FVCA_HYPERVISOR_EPOCH_ACCEPTED 1 1", b"FVCA_TRIAL_ATTEMPTS_EXHAUSTED " + txn + b" 3", finish,
            ), args.output)
        else:
            assert not resets
            standing["require_sequence"](candidate_boot, (guest_ready, disarmed, healthy), args.output)
        print(f"{case} passed", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for value in ("fixture", "members", "maintenance-initrd", "seed", "kernel", "firmware", "variables",
                  "tpm-state", "sign-key", "output"):
        parser.add_argument(f"--{value}", type=lambda path: Path(path).resolve(), required=True)
    for value in ("epoch-policy", "core", "runtime", "guest"):
        parser.add_argument(f"--{value}", required=True)
    parser.add_argument("--case", choices=("expiry", "healthy"), help="run one case instead of both")
    options = parser.parse_args()
    options.output.mkdir(mode=0o700)
    qualify(options)
