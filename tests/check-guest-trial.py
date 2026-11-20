#!/usr/bin/env python3
"""Verify a staged Guest release and reject two tampered inputs in disposable KVM."""

import argparse
import gzip
import os
from pathlib import Path
import re
import runpy
import subprocess
import tempfile
from types import SimpleNamespace


PREPARE = b"""#!/bin/bash
set -Eeuo pipefail
export PATH=/usr/bin
trap 'echo FVCA_GUEST_TRIAL_FIXTURE_FAILED; poweroff -f' ERR
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
[[ -d /sys/fs/btrfs/$filesystem_uuid && $(</sys/block/vdc/serial) == fvca-trial-candidate ]]
root=/mnt/guest-updates
bundle=$(</bundle)
mkdir "$root" "$root/$bundle"
cp /approval "$root/pending-trial"
cp /bad-signature "$root/test-bad-signature"
cp /bad-image "$root/test-bad-image"
cp --sparse=always /dev/vdc "$root/$bundle/guest-boot.raw"
sync
umount /mnt
echo FVCA_GUEST_TRIAL_FIXTURE_INSTALLED
poweroff -f
"""


def install(args, work, members):
    archive = work / "tree"
    archive.mkdir()
    with gzip.open(args.lab / "lab.cpio.gz", "rb") as source:
        subprocess.run(["cpio", "--quiet", "-id", "--no-absolute-filenames", "--no-preserve-owner"],
                       cwd=archive, input=source.read(), check=True)
    init = archive / "init"
    init.write_bytes(PREPARE)
    init.chmod(0o755)
    envelope = args.approval.read_bytes()
    body = envelope[64:]
    root = re.search(rb"\nbundle=([0-9a-f]{64})\n", body)[1]
    (archive / "bundle").write_bytes(root + b"\n")
    (archive / "approval").write_bytes(envelope)
    (archive / "bad-signature").write_bytes(bytes([envelope[0] ^ 1]) + envelope[1:])
    alternate = work / "bad-image.body"
    alternate.write_bytes(re.sub(rb"candidate_image_sha256=[0-9a-f]{64}", b"candidate_image_sha256=" + b"0" * 64,
                                 body, count=1))
    proof = subprocess.check_output(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", args.sign_key,
                                     "-in", alternate])
    (archive / "bad-image").write_bytes(proof + alternate.read_bytes())
    listing = b"".join(os.fsencode(path.relative_to(archive)) + b"\0" for path in sorted(archive.rglob("*")))
    packed = subprocess.check_output(["cpio", "--quiet", "-o", "-0", "-H", "newc", "--owner=0:0"],
                                     cwd=archive, input=listing)
    initrd = work / "initrd.cpio.gz"
    initrd.write_bytes(gzip.compress(packed, compresslevel=1, mtime=0))
    argv = ["qemu-system-x86_64", "-machine", "q35", "-accel", "kvm", "-cpu", "host",
            "-m", "2048", "-smp", "2", "-display", "none", "-monitor", "none", "-no-reboot", "-nic", "none",
            "-serial", "stdio", "-kernel", args.kernel, "-initrd", initrd,
            "-append", "rdinit=/init console=ttyS0 quiet panic=1"]
    for name, image, mode in zip(("a", "b", "candidate"), (*members, args.candidate), ("", "", ",readonly=on"), strict=True):
        if "," in str(image):
            raise ValueError("expected comma-free disposable fixture paths")
        argv += ["-drive", f"if=none,format=raw,id={name}{mode},file={image}",
                 "-device", f"virtio-blk-pci,drive={name},serial=fvca-trial-{name}"]
    log = args.output / "install.log"
    with log.open("wb") as transcript:
        subprocess.run(argv, stdout=transcript, stderr=subprocess.STDOUT, check=True, timeout=90)
    assert b"FVCA_GUEST_TRIAL_FIXTURE_INSTALLED" in log.read_bytes(), log


def qualify(args):
    storage = runpy.run_path(Path(__file__).with_name("check-storage.py"))
    with tempfile.TemporaryDirectory(prefix="disposable-", dir=args.output) as directory:
        work = Path(directory)
        members = [work / f"member-{side}.raw" for side in ("a", "b")]
        for member in members:
            subprocess.run(["cp", "--reflink=auto", "--sparse=always", args.lab / member.name, member], check=True)
        install(args, work, members)
        options = SimpleNamespace(disk=args.disk, runtime=None, guest=False, output=args.output, variables=args.variables,
                                  nvme_boot=True, boot_sector_size=4096, no_default_devices=True, memory_mib=4096)
        finish = b"FVCA_GUEST_TRIAL_QUALIFIED"
        for attempt in range(1, 4):
            prompts, log = storage["boot"](
                options, f"guest-trial-{attempt}", (args.lab / "storage.key").read_bytes(), *members,
                firmware=args.firmware, firmware_timeout=35, timeout=170, ready_marker=finish,
            )
            if b"Linux version " in log:
                break
    log = storage["rejoin_serial_output"](log)
    assert prompts == 2 and storage["FAIL"] not in log and b"secureboot: Secure boot enabled" in log
    assert b"FVCA_HOST_STORAGE_AUTHENTICATED" in log and b"FVCA_SELINUX_ENFORCING" in log
    assert log.count(b"FVCA_SERVICE_GUEST_READY") == 1 and b"FVCA_SERVICE_GUEST_STOPPED" not in log
    assert log.count(b"FVCA_GUEST_TRIAL_PREPARED") == 1
    position = 0
    for marker in (b"FVCA_SERVICE_GUEST_READY", b"FVCA_GUEST_TRIAL_PREPARED", b"Ed25519 signature",
                   b"staged Guest image differs from the signed trial", finish):
        position = log.index(marker, position) + len(marker)
    print("Verified staged Guest boot materials and retained the running Guest across both refusals")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("disk", "candidate", "lab", "approval", "sign-key", "firmware", "variables", "kernel", "output"):
        parser.add_argument(f"--{name}", required=True, type=lambda value: Path(value).resolve())
    args = parser.parse_args()
    args.output.mkdir(mode=0o700)
    qualify(args)
