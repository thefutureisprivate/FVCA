#!/usr/bin/env python3
"""Qualify signed Hypervisor promotion using disposable KVM disks and firmware."""

import argparse
import gzip
import json
import os
import re
from pathlib import Path
import runpy
import shutil
import struct
import subprocess
import tempfile
from types import SimpleNamespace
from uuid import UUID


INSTALL = b"""#!/bin/bash
set -Eeuo pipefail
export PATH=/usr/bin
trap 'echo FVCA_PROMOTION_FIXTURE_FAILED; poweroff -f' ERR
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
modprobe dm-crypt
. /lab-ids
umask 077
tx=$(</promotion-transaction)
[[ $tx =~ ^[0-9a-f-]{36}$ ]]
for side in a b; do
    drive=/dev/vd$side
    for _ in {1..30}; do
        [[ -b ${drive}1 ]] && break
        sleep 0.1
    done
    [[ $(</sys/block/vd$side/serial) == fvca-lab-$side ]]
    cryptsetup open --type=luks2 --key-file=/storage.key "${drive}1" "fvca-test-$side"
done
mount -t btrfs -o nodev,nosuid,noexec,device=/dev/mapper/fvca-test-b /dev/mapper/fvca-test-a /mnt
[[ -d /sys/fs/btrfs/$filesystem_uuid && ! -L /mnt/boot-trials ]]
[[ -f /mnt/boot-trials/$tx.healthy && ! -e /mnt/boot-trials/$tx.promotion && ! -L /mnt/boot-trials/$tx.promotion ]]
cp /promotion-envelope /mnt/boot-trials/$tx.promotion
chmod 0600 /mnt/boot-trials/$tx.promotion
sync
umount /mnt
cryptsetup close fvca-test-b
cryptsetup close fvca-test-a
echo FVCA_PROMOTION_FIXTURE_INSTALLED
poweroff -f
"""


def variables(path, trial):
    return trial["Edk2VarStore"](path).get_varlist()


def boot_state(path, trial):
    records = variables(path, trial)
    override = records.get("BootNext")
    order = tuple(entry[0] for entry in struct.iter_unpack("<H", records["BootOrder"].data))
    return order, override.data if override is not None else None


def clone(source, destination):
    subprocess.run(["cp", "--reflink=auto", "--sparse=always", "--", source, destination], check=True)
    return destination


def install(args, output, members, packet):
    with tempfile.TemporaryDirectory(prefix="fvca-promotion-lab-") as work:
        work = Path(work)
        root = work / "initrd"
        root.mkdir()
        with gzip.open(args.lab / "lab.cpio.gz", "rb") as source:
            subprocess.run(["cpio", "--quiet", "-id", "--no-absolute-filenames", "--no-preserve-owner"],
                           cwd=root, input=source.read(), check=True)
        (root / "install-promotion").write_bytes(INSTALL)
        (root / "install-promotion").chmod(0o755)
        (root / "promotion-transaction").write_text(f"{args.transaction}\n", encoding="ascii")
        shutil.copyfile(packet, root / "promotion-envelope")
        contents = b"".join(os.fsencode(item.relative_to(root)) + b"\0" for item in sorted(root.rglob("*")))
        archive = subprocess.run(["cpio", "--quiet", "-o", "-0", "-H", "newc", "--owner=0:0"], cwd=root,
                                 input=contents, stdout=subprocess.PIPE, check=True).stdout
        initrd = work / "fixture.initrd.gz"
        initrd.write_bytes(gzip.compress(archive, compresslevel=1, mtime=0))
        command = ["qemu-system-x86_64", "-machine", "q35", "-accel", "kvm", "-cpu", "host", "-m", "1024", "-smp", "2",
                   "-display", "none", "-monitor", "none", "-no-reboot", "-nic", "none",
                   "-serial", "stdio", "-kernel", f"/usr/lib/modules/{args.kernel}/vmlinuz", "-initrd", initrd,
                   "-append", "rdinit=/install-promotion console=ttyS0 quiet"]
        for side, member in zip(("a", "b"), members, strict=True):
            member = member.resolve(strict=True)
            if "," in str(member):
                raise ValueError("fixture disk paths must be comma-free")
            command += ["-drive", f"if=none,format=raw,id={side},file={member}",
                        "-device", f"virtio-blk-pci,drive={side},serial=fvca-lab-{side}"]
        logfile = output / "install.log"
        with logfile.open("wb") as log:
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=45)
        if b"FVCA_PROMOTION_FIXTURE_INSTALLED" not in logfile.read_bytes():
            raise ValueError("could not install promotion packet on the disposable mirror")


def qualify(args):
    tests = Path(__file__).parent
    trial = runpy.run_path(tests / "check-hypervisor-trial.py")
    lab = runpy.run_path(tests / "check-storage.py")
    esp_a, esp_b = trial["esp"](args.stable), trial["esp"](args.candidate)
    stable, candidate = trial["STABLE"], trial["CANDIDATE"]
    tx = str(args.transaction).encode()
    args.output.mkdir(mode=0o700)
    password = (args.lab / "storage.key").read_bytes()

    def fixture(name, from_state=None):
        output = args.output / name
        output.mkdir(mode=0o700)
        store = output / "vars.fd"
        if from_state is None:
            trial["prepare_vars"](args.variables, store, esp_a, esp_b)
            input_members = [args.lab / f"member-{side}.raw" for side in ("a", "b")]
        else:
            clone(from_state[1], store)
            input_members = from_state[2]
        return output, store, [clone(member, output / member.name) for member in input_members]

    def run(state, phase, ready, *, companion=None, required=(), prohibited=(), recovery_override=False):
        output, store, members = state
        opts = SimpleNamespace(guest=False, disk=args.stable, runtime=companion or args.candidate, variables=store,
                               output=output, nvme_boot=True, boot_sector_size=4096, persistent_boot=True,
                               memory_mib=4096, no_default_devices=True)
        before = boot_state(store, trial)[1]
        for attempt in range(1, 4):
            prompts, log = lab["boot"](opts, f"{phase}-{attempt}", password, *members, ready_marker=ready,
                                       timeout=135, firmware_timeout=36)
            if b"Kernel command line:" in log:
                break
            if boot_state(store, trial)[1] != before:
                if not recovery_override or attempt == 3:
                    break
                # This selects the fallback in the fixture. Never restore a consumed trial override.
                edk = trial["Edk2VarStore"](store)
                values = edk.get_varlist()
                values.set_boot_next(stable)
                edk.write_varstore(store, values)
        # Kernel printk can interrupt the userspace profile report mid-line.
        log = lab["KERNEL_MOUNT_NOTICE"].sub(b"", lab["KERNEL_AUDIT"].sub(b"", log))
        if (prompts != 2 or not all(item in log for item in (
                ready, b"Secure boot enabled", lab["HOST_PROFILES"], b"FVCA_SELINUX_ENFORCING", *required))
                or any(item in log for item in prohibited)):
            raise ValueError(f"{phase} did not reach the expected state. See logs in {output}")
        print(f"{phase} passed", flush=True)
        return log

    ready = fixture("trial")
    run(ready, "stable-armed", b"FVCA_TRIAL_ARMED " + tx + b" 000b")
    old, next_boot = boot_state(ready[1], trial)
    if old[:2] != (stable, candidate) or next_boot != struct.pack("<H", candidate):
        raise ValueError("unexpected armed firmware state")
    new = (candidate, stable, *old[2:])
    transcript = run(ready, "candidate-healthy", b"FVCA_TRIAL_HEALTH_RECORDED " + tx)
    boot_id = re.search(rb"FVCA_TRIAL_CANDIDATE_STARTED " + tx + rb" ([0-9a-f-]{36})", transcript)[1].decode()
    fields = dict(line.split("=", 1) for line in args.trial.read_text().splitlines()[1:])
    health = args.output / "health"
    health.write_text(f"FVCA-HYPERVISOR-TRIAL-HEALTH-1\ntransaction={args.transaction}\nboot_id={boot_id}\n"
                      f"candidate={fields['candidate'].split(',')[1]}\ncandidate_esp_sha256={fields['candidate_esp_sha256']}\n"
                      f"core_root={fields['candidate_core']}\nguest_bundle={fields['guest_bundle']}\n"
                      f"vm_runtime={fields['candidate_runtime']}\n", encoding="ascii")

    def sign(output, key):
        subprocess.run(["python3", tests.parent / "tools/sign-hypervisor-promotion.py", "--trial", args.trial,
                        "--health", health, "--candidate", args.candidate, "--sign-key", key,
                        "--stable-core", args.stable_core, "--stable-runtime", args.stable_runtime,
                        "--output", output], check=True)
        return output

    valid = sign(args.output / "approval", args.sign_key)
    wrong = fixture("wrong-signer", ready)
    install(args, wrong[0], wrong[2], sign(args.output / "wrong-approval", args.wrong_key))
    run(wrong, "wrong-signature-refused", b"boot promotion requires an independently signed approval",
        prohibited=(b"FVCA_BOOT_PROMOTED",))
    if boot_state(wrong[1], trial) != (old, None):
        raise ValueError("invalid authorization changed the firmware selection")

    unauthorized = fixture("unauthorized-default", ready)
    edk = trial["Edk2VarStore"](unauthorized[1])
    values = edk.get_varlist()
    values["BootOrder"].data = struct.pack(f"<{len(new)}H", *new)
    edk.write_varstore(unauthorized[1], values)
    run(unauthorized, "default-without-approval-refused", b"default candidate lacks a durable promotion approval",
        prohibited=(b"FVCA_PROMOTED_HYPERVISOR_ACTIVE", b"FVCA_TRIAL_CANDIDATE_STARTED", b"FVCA_SERVICE_GUEST_READY"))
    if boot_state(unauthorized[1], trial) != (new, None):
        raise ValueError("unapproved default boot changed the firmware selection")

    damaged = fixture("damaged-candidate", ready)
    install(args, damaged[0], damaged[2], valid)
    copy = clone(args.candidate, damaged[0] / "candidate.raw")
    table = json.loads(subprocess.check_output(["sfdisk", "--json", "--sector-size", "4096", copy]))["partitiontable"]
    part = next(row for row in table["partitions"] if row["name"] == "fvca-runtime")
    with copy.open("r+b") as disk:
        disk.seek(part["start"] * 4096)
        byte = disk.read(1)[0]
        disk.seek(-1, 1)
        disk.write(bytes([byte ^ 1]))
    log = run(damaged, "invalid-verity-refused", b'FVCA_TRIAL_REFUSED "/usr/bin/veritysetup" exited', companion=copy)
    if b"FVCA_BOOT_PROMOTED" in log or boot_state(damaged[1], trial) != (old, None):
        raise ValueError("damaged candidate changed the firmware selection")

    install(args, ready[0], ready[2], valid)
    run(ready, "promotion-written", b"FVCA_BOOT_PROMOTED " + tx)
    if boot_state(ready[1], trial) != (new, None):
        raise ValueError("promotion did not preserve the recovery entry and remaining order")
    guest_ready = b"FVCA_SERVICE_GUEST_READY"
    run(ready, "candidate-default-boot", lab["READY"],
        required=(b"FVCA_PROMOTED_HYPERVISOR_ACTIVE " + tx, guest_ready),
        prohibited=(b"FVCA_TRIAL_CANDIDATE_STARTED", lab["FAIL"]))
    store = trial["Edk2VarStore"](ready[1])
    values = store.get_varlist()
    values.set_boot_next(stable)
    store.write_varstore(ready[1], values)
    run(ready, "stable-recovery-boot", lab["READY"], recovery_override=True,
        required=(b"FVCA_PROMOTION_STABLE_RECOVERY " + tx, guest_ready),
        prohibited=(b"FVCA_BOOT_PROMOTED", b"FVCA_TRIAL_ARMED", lab["FAIL"]))
    if boot_state(ready[1], trial) != (new, None):
        raise ValueError("recovery selection changed the promoted boot order")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("stable", "candidate", "variables", "lab", "trial", "sign-key", "wrong-key", "output"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--transaction", type=UUID, required=True)
    parser.add_argument("--stable-core", required=True)
    parser.add_argument("--stable-runtime", required=True)
    parser.add_argument("--kernel", default=os.uname().release)
    qualify(parser.parse_args())


if __name__ == "__main__":
    main()
