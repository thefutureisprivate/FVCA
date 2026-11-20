#!/usr/bin/env python3
"""Exercise the standing Host trial inbox using disposable KVM disks and firmware."""

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import struct
import subprocess
import tempfile
import time
from types import SimpleNamespace
from uuid import UUID


INSTALL = b"""#!/bin/bash
set -Eeuo pipefail
export PATH=/usr/bin
trap 'echo FVCA_TRIAL_FIXTURE_FAILED; poweroff -f' ERR
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
. /lab-ids
for module in dm_crypt dm_integrity authenc hmac xts; do modprobe "$module"; done
umask 077
for side in a b; do
    [[ $(</sys/block/vd$side/serial) == fvca-trial-$side ]]
    cryptsetup open --type luks2 --key-file=/storage.key "/dev/vd${side}1" "fvca-trial-$side"
done
mount -t btrfs -o device=/dev/mapper/fvca-trial-b /dev/mapper/fvca-trial-a /mnt
[[ -d /sys/fs/btrfs/$filesystem_uuid ]]
mkdir -m 0700 /mnt/boot-trials
if [[ -f /invalid-envelope ]]; then
    cp /envelope /mnt/boot-trials/test-trial
    cp /invalid-envelope /mnt/boot-trials/test-invalid-trial
    chmod 0600 /mnt/boot-trials/test-{trial,invalid-trial}
else
    cp /envelope /mnt/boot-trials/pending-trial
    chmod 0600 /mnt/boot-trials/pending-trial
fi
if [[ -b /dev/vdc ]]; then
    [[ $(</sys/block/vdc/serial) == fvca-trial-seed ]]
    test -f /mnt/vms/service-guest/data.raw
    rm -- /mnt/vms/service-guest/data.raw
    cp --sparse=always /dev/vdc /mnt/vms/service-guest/data.raw
    chmod 0600 /mnt/vms/service-guest/data.raw
fi
sync
umount /mnt
echo FVCA_TRIAL_FIXTURE_INSTALLED
poweroff -f
"""


def install(args, output, members, envelope, seed=None):
    with tempfile.TemporaryDirectory(prefix="fvca-trial-fixture-") as work:
        root = Path(work)
        archive = root / "archive"
        archive.mkdir()
        with gzip.open(args.maintenance_initrd, "rb") as source:
            subprocess.run(["cpio", "--quiet", "-id", "--no-absolute-filenames", "--no-preserve-owner"],
                           cwd=archive, input=source.read(), check=True)
        init = archive / "init"
        init.write_bytes(INSTALL)
        init.chmod(0o755)
        (archive / "envelope").write_bytes(envelope)
        if args.online_handoff and seed is not None:
            (archive / "invalid-envelope").write_bytes(bytes([envelope[0] ^ 1]) + envelope[1:])
        listing = b"".join(os.fsencode(path.relative_to(archive)) + b"\0" for path in sorted(archive.rglob("*")))
        payload = subprocess.run(["cpio", "--quiet", "-o", "-0", "-H", "newc", "--owner=0:0"],
                                 cwd=archive, input=listing, stdout=subprocess.PIPE, check=True).stdout
        initrd = root / "fixture.cpio.gz"
        initrd.write_bytes(gzip.compress(payload, compresslevel=1, mtime=0))
        argv = ["qemu-system-x86_64", "-machine", "q35", "-accel", "kvm", "-cpu", "host",
                "-m", "2048", "-smp", "2", "-display", "none", "-monitor", "none", "-no-reboot", "-nic", "none",
                "-serial", "stdio", "-kernel", args.kernel, "-initrd", initrd,
                "-append", "rdinit=/init console=ttyS0 quiet panic=1"]
        disks = [(label, member, "") for label, member in zip(("a", "b"), members, strict=True)]
        if seed is not None:
            disks.append(("seed", seed, ",readonly=on"))
        for label, path, mode in disks:
            if "," in str(path):
                raise ValueError("fixture paths must be comma-free")
            argv += ["-drive", f"if=none,format=raw,id={label},file={path}{mode}",
                     "-device", f"virtio-blk-pci,drive={label},serial=fvca-trial-{label}"]
        with output.open("wb") as log:
            subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=60)
        assert b"FVCA_TRIAL_FIXTURE_INSTALLED" in output.read_bytes(), output


def require_sequence(log, markers, output):
    position = 0
    for marker in markers:
        offset = log.find(marker, position)
        assert offset >= 0, (output, marker)
        position = offset + len(marker)

def candidate_fields(image):
    table = json.loads(subprocess.check_output(["sfdisk", "--json", "--sector-size", "4096", image]))
    parts = {part["name"]: part for part in table["partitiontable"]["partitions"]}
    esp = parts["fvca-esp"]
    offset, size = esp["start"] * 4096, esp["size"] * 4096
    sha = hashlib.sha256()
    with image.open("rb") as source:
        source.seek(offset)
        remaining = size
        while remaining:
            chunk = source.read(min(remaining, 1024 * 1024))
            if not chunk:
                raise ValueError("truncated candidate ESP")
            sha.update(chunk)
            remaining -= len(chunk)
    with tempfile.TemporaryDirectory(prefix="fvca-trial-uki-") as directory:
        loader = Path(directory) / "BOOTX64.EFI"
        subprocess.run(["mcopy", "-i", f"{image}@@{offset}", "::/EFI/BOOT/BOOTX64.EFI", loader], check=True)
        with loader.open("rb") as source:
            uki = hashlib.file_digest(source, "sha256").hexdigest()
        loader_size = loader.stat().st_size
    bound = f"candidate_uki_sha256={uki}\ncandidate_uki_bytes={loader_size}\n"
    for name in ("core", "runtime", "guest"):
        data = parts[f"fvca-{name}"]["uuid"].lower()
        tree = parts[f"fvca-{name}_verity"]["uuid"].lower()
        bound += f"candidate_{name}_devices={data},{tree}\n"
    return bound, f"candidate_esp_sha256={sha.hexdigest()}\ncandidate_esp_bytes={size}\n"


def qualify(args):
    here = Path(__file__).parent
    trial = runpy.run_path(here / "check-hypervisor-trial.py")
    storage = runpy.run_path(here / "check-storage.py")
    stable, candidate = (args.fixture / f"{name}.raw" for name in ("stable", "candidate"))
    first, second = trial["esp"](stable), trial["esp"](candidate)
    binding, esp = candidate_fields(candidate)
    ts = int(time.time())
    tx = str(args.transaction)
    args.output.mkdir(mode=0o700)

    for label, key, expiry, stable_core, refusal in (
        ("wrong-signature", args.wrong_key, ts + 1800, args.core,
         b"boot trial requires an independently signed approval"),
        ("expired", args.sign_key, ts - 1, args.core, b"standing trial is outside its signed validity interval"),
        ("different-stable", args.sign_key, ts + 1800, "a" * 64,
         b"standing trial differs from the running stable composition"),
        ("approved", args.sign_key, ts + 1800, args.core, None),
    ):
        output = args.output / label
        output.mkdir(mode=0o700)
        with tempfile.TemporaryDirectory(prefix="disposable-", dir=output) as work:
            work = Path(work)
            variables = output / "vars.fd"
            trial["prepare_vars"](args.variables, variables, first, second)
            body = work / "payload"
            body.write_text(
                f"FVCA-HYPERVISOR-STANDING-TRIAL-2\nnot_before={ts-60}\nexpires={expiry}\n"
                f"stable_epoch=1\ncandidate_epoch=2\nepoch_policy_sha256={args.epoch_policy}\n"
                f"stable_core={stable_core}\nstable_runtime={args.runtime}\nstable_guest_bundle={args.guest}\n"
                f"{binding}FVCA-HYPERVISOR-TRIAL-2\ntransaction={tx}\n"
                f"stable=000a,{first[1]['uuid'].lower()}\ncandidate=000b,{second[1]['uuid'].lower()}\n"
                f"{esp}"
                f"candidate_core={args.core}\ncandidate_runtime={args.runtime}\nguest_bundle={args.guest}\n",
                encoding="ascii",
            )
            signature = subprocess.check_output(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", key, "-in", body])
            envelope = (args.delivered_envelope.read_bytes() if refusal is None and args.delivered_envelope is not None
                        else signature + body.read_bytes())
            members = [work / f"member-{side}.raw" for side in ("a", "b")]
            for member in members:
                subprocess.run(["cp", "--reflink=auto", "--sparse=always", args.members / member.name, member], check=True)
            install(args, output / "install.log", members, envelope,
                    args.seed if refusal is None else None)
            options = SimpleNamespace(disk=stable, runtime=candidate, guest=False, output=output, variables=variables,
                                      nvme_boot=True, persistent_boot=True, boot_sector_size=4096,
                                      no_default_devices=True, memory_mib=4096, trial_watchdog=True)

            def override():
                entry = trial["Edk2VarStore"](variables).get_varlist().get("BootNext")
                return entry.data if entry is not None else None

            def boot(phase, marker, *, allow_reboot=False):
                before = override()
                for retry in range(1, 4):
                    with storage["software_tpm"](args.tpm_state) as socket:
                        prompts, log = storage["boot"](options, f"{phase}-{retry}", None, *members,
                                                        firmware=args.firmware, tpm_socket=socket,
                                                        firmware_timeout=35, timeout=260 if args.online_handoff else 115,
                                                        ready_marker=marker,
                                                        allow_reboot=allow_reboot)
                    if b"Kernel command line:" in log or override() != before:
                        break
                log = storage["rejoin_serial_output"](log)
                assert prompts == 0 and marker in log and storage["FAIL"] not in log, (output, phase)
                assert b"secureboot: Secure boot enabled" in log and b"FVCA_SELINUX_ENFORCING" in log
                assert b"FVCA_HOST_STORAGE_UNLOCK_PROFILE tpm2-auto" in log
                order = trial["Edk2VarStore"](variables).get_varlist()["BootOrder"].data
                assert order[:4] == struct.pack("<HH", trial["STABLE"], trial["CANDIDATE"])
                return log

            armed = f"FVCA_TRIAL_ARMED {tx}".encode()
            reboot_requested = b"FVCA_TRIAL_REBOOT_REQUESTED"
            if refusal is not None:
                log = boot("stable-refusal", b"FVCA_TRIAL_REFUSED " + refusal)
                assert armed not in log and reboot_requested not in log and override() is None
            else:
                healthy = f"FVCA_TRIAL_HEALTH_RECORDED {tx}".encode()
                log = boot("automatic-trial", healthy, allow_reboot=True)
                if args.online_handoff:
                    live_log, live_reset, log = log.partition(b"reboot: Restarting system")
                    assert live_reset and armed not in live_log and reboot_requested not in live_log, output
                    drained = f"FVCA_HYPERVISOR_TRIAL_DRAINED {tx}".encode()
                    markers = (b"FVCA_SERVICE_GUEST_READY", b"FVCA_ONLINE_TRIAL_INVALID_REFUSED",
                               b"FVCA_ONLINE_TRIAL_CAPTURE_DEFERRED", b"FVCA_SERVICE_GUEST_STOPPED",
                               drained, b"FVCA_SERVICE_GUEST_READY",
                               b"FVCA_HYPERVISOR_ACTIVATION_RECOVERED", b"FVCA_SERVICE_GUEST_STOPPED",
                               drained)
                    require_sequence(live_log, markers, output)
                stable_log, reset, candidate_log = log.partition(b"reboot: Restarting system")
                assert reset and reset not in candidate_log, output
                for boot_log, markers in (
                    (stable_log, (b"FVCA_HYPERVISOR_EPOCH_ACCEPTED 1 1", armed + b" 000b", reboot_requested)),
                    (candidate_log, (b"FVCA_HYPERVISOR_EPOCH_ACCEPTED 2 1",
                                     f"FVCA_TRIAL_CANDIDATE_STARTED {tx}".encode(),
                                     b"FVCA_SERVICE_GUEST_READY", healthy)),
                ):
                    assert all(marker in boot_log for marker in (b"secureboot: Secure boot enabled",
                                                                 b"FVCA_SELINUX_ENFORCING",
                                                                 b"FVCA_HOST_STORAGE_UNLOCK_PROFILE tpm2-auto"))
                    require_sequence(boot_log, markers, output)
                assert all(marker not in stable_log for marker in (b"FVCA_VM_RUNTIME_ACTIVE", b"FVCA_DEV_BASE_READY",
                                                                   b"FVCA_SERVICE_GUEST_READY"))
                assert override() is None
                log = boot("stable-replay", f"FVCA_TRIAL_HEALTH_AVAILABLE {tx}".encode())
                assert armed not in log and reboot_requested not in log and override() is None
        print(f"{label} passed", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for value in ("fixture", "members", "maintenance-initrd", "seed", "kernel", "firmware", "variables",
                  "tpm-state", "sign-key", "wrong-key", "output"):
        parser.add_argument(f"--{value}", type=lambda path: Path(path).absolute(), required=True)
    for value in ("epoch-policy", "core", "runtime", "guest"):
        parser.add_argument(f"--{value}", required=True)
    parser.add_argument("--transaction", type=UUID, required=True)
    parser.add_argument("--delivered-envelope", type=lambda path: Path(path).absolute(),
                        help="use the delivered packet for the approved boot case")
    parser.add_argument("--online-handoff", action="store_true",
                        help="start with a running Guest using a stable UKI with the online-trial lab unit")
    os.umask(0o077)
    qualify(parser.parse_args())
