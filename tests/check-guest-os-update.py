#!/usr/bin/env python3
"""Qualify the enrolled Guest update timer against a signed local TUF depot."""

import argparse
from datetime import UTC, datetime
import gzip
import os
from pathlib import Path
import re
import runpy
import subprocess
import tempfile
from types import SimpleNamespace

from securesystemslib.signer import CryptoSigner
from tuf.api.metadata import TargetFile


PREPARE = b"""#!/bin/bash
set -Eeuo pipefail
export PATH=/usr/bin
trap 'echo FVCA_GUEST_UPDATE_FIXTURE_FAILED; poweroff -f' ERR
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
. /lab-ids
for module in dm_crypt dm_integrity authenc hmac xts; do modprobe "$module"; done
umask 077
for side in a b; do
    [[ $(</sys/block/vd$side/serial) == fvca-update-$side ]]
    cryptsetup open --type luks2 --key-file=/storage.key "/dev/vd${side}1" "fvca-update-$side"
done
mount -t btrfs -o device=/dev/mapper/fvca-update-b /dev/mapper/fvca-update-a /mnt
[[ -d /sys/fs/btrfs/$filesystem_uuid && $(</sys/block/vdc/serial) == fvca-update-depot ]]
mkdir /seed /mnt/guest-os-update
mount -t btrfs -o ro,rescue=nologreplay,nodev,nosuid,noexec /dev/vdc /seed
cp -R /seed/. /mnt/guest-os-update/
umount /seed
sync
umount /mnt
echo FVCA_GUEST_UPDATE_FIXTURE_INSTALLED
poweroff -f
"""


def public_key(key):
    der = subprocess.check_output(["openssl", "pkey", "-in", key, "-pubout", "-outform", "DER"])
    assert der[:12] == bytes.fromhex("302a300506032b6570032100") and len(der) == 44
    return der[12:]


def provision_depot(args, work, trial):
    intake = runpy.run_path(Path(__file__).with_name("check-release-intake.py"))
    state = work / "state"
    state.mkdir(mode=0o700)
    depot = state / "depot"
    depot.mkdir(mode=0o700)
    targets = depot / "targets"
    targets.mkdir()
    qualification = work / "qualification.json"
    intake["write_json"](qualification, {"profile": "disposable Guest update qualification"})
    selection, sources = intake["make_release"](work, {
        "guest-boot.raw": args.candidate,
        "qualification.json": qualification,
    }, trial.candidate_epoch, "service-guest")
    stem = intake["target_prefix"](selection)
    now = datetime.now(UTC).replace(microsecond=0)
    since = int(now.timestamp())
    qualification_key = CryptoSigner.generate_ed25519()
    channel = work / "fvca-os-service-guest-stable.json"
    proof = channel.with_suffix(".sig")
    candidate = {
        "epoch": trial.candidate_epoch, "manifest_sha256": selection["manifest_sha256"],
        "activation": {"urgency": "routine"} if args.routine else {"urgency": "security", "activate_by": since + 900},
        "trial_approval": {"bytes": args.approval.stat().st_size, "sha256": intake["sha256"](args.approval)},
    }
    intake["write_json"](channel, {
        "schema": "fvca-os-channel-v1", "role": "service-guest", "channel": "stable",
        "sequence": 2, "valid_from": since - 300, "expires": since + 3600,
        "compatibility_sha256": "a" * 64, "release": candidate,
    })
    proof.write_bytes(bytes.fromhex(qualification_key.sign(channel.read_bytes()).signature))
    sources.update({channel.name: channel, proof.name: proof, f"{stem}-guest-trial.bin": args.approval})
    published = {}
    for name, source in sources.items():
        target = TargetFile.from_file(name, str(source), ["sha256"])
        os.link(source, targets / f"{target.hashes['sha256']}.{name}")
        published[name] = target
    intake["publish"](depot, (1, 1), intake["new_keys"](), now, published)
    (state / "trusted-root.json").write_bytes((depot / "metadata/1.root.json").read_bytes())
    config_digest = intake["write_json"](state / "depot.json", {
        "transport": "local", "path": "/run/fvca/host-data/guest-os-update/depot",
    })
    start = (now.hour * 60 + now.minute + 60) % 1440
    policy = state / "policy.json"
    intake["write_json"](policy, {
        "schema": "fvca-os-update-policy-v1", "revision": 1, "role": "service-guest", "channel": "stable",
        "enabled": True, "valid_from": since - 300, "expires": since + 3600,
        "tuf_root_sha256": intake["sha256"](state / "trusted-root.json"), "depot_config_sha256": config_digest,
        "qualification_key_ed25519": qualification_key.public_key.keyval["public"],
        "trial_key_ed25519": public_key(args.trial_key).hex(), "compatibility_sha256": "a" * 64,
        "minimum_epoch": trial.stable_epoch, "max_release_bytes": 1024**3, "max_staged_bytes": 2 * 1024**3,
        "maintenance": {"timezone": "UTC", "start_minute": start, "end_minute": (start + 20) % 1440},
    })
    (state / "policy.sig").write_bytes(subprocess.check_output([
        "openssl", "pkeyutl", "-sign", "-rawin", "-inkey", args.owner_key, "-in", policy,
    ]))
    intake["write_json"](state / "active-os-release.json", {
        "role": "service-guest", "sequence": 1, "epoch": trial.stable_epoch,
        "manifest_sha256": "b" * 64, "guest_bundle": trial.stable.decode(),
    })
    image = work / "depot.raw"
    with image.open("wb") as raw:
        raw.truncate(1024**3)
    subprocess.run(["mkfs.btrfs", "--quiet", "--rootdir", state, image], check=True)
    return image, candidate["manifest_sha256"].encode()


def install(args, work, members, depot):
    archive = work / "tree"
    archive.mkdir()
    with gzip.open(args.lab / "lab.cpio.gz", "rb") as source:
        subprocess.run(["cpio", "--quiet", "-id", "--no-absolute-filenames", "--no-preserve-owner"],
                       cwd=archive, input=source.read(), check=True)
    (archive / "init").write_bytes(PREPARE)
    (archive / "init").chmod(0o755)
    listing = b"".join(os.fsencode(path.relative_to(archive)) + b"\0" for path in sorted(archive.rglob("*")))
    packed = subprocess.check_output(["cpio", "--quiet", "-o", "-0", "-H", "newc", "--owner=0:0"],
                                     cwd=archive, input=listing)
    initrd = work / "initrd.cpio.gz"
    initrd.write_bytes(gzip.compress(packed, compresslevel=1, mtime=0))
    argv = ["qemu-system-x86_64", "-machine", "q35", "-accel", "kvm", "-cpu", "host", "-m", "2048", "-smp", "2",
            "-display", "none", "-monitor", "none", "-no-reboot", "-nic", "none", "-serial", "stdio",
            "-kernel", args.kernel, "-initrd", initrd, "-append", "rdinit=/init console=ttyS0 quiet panic=1"]
    for name, image, mode in zip(("a", "b", "depot"), (*members, depot), ("", "", ",readonly=on"), strict=True):
        if "," in str(image):
            raise ValueError("expected comma-free disposable fixture paths")
        argv += ["-drive", f"if=none,format=raw,id={name}{mode},file={image}",
                 "-device", f"virtio-blk-pci,drive={name},serial=fvca-update-{name}"]
    log = args.output / "install.log"
    with log.open("wb") as transcript:
        subprocess.run(argv, stdout=transcript, stderr=subprocess.STDOUT, check=True, timeout=90)
    assert b"FVCA_GUEST_UPDATE_FIXTURE_INSTALLED" in log.read_bytes(), log


def qualify(args):
    harness = runpy.run_path(Path(__file__).with_name("check-guest-trial.py"))
    storage = runpy.run_path(Path(__file__).with_name("check-storage.py"))
    body = args.approval.read_bytes()[64:]
    trial = SimpleNamespace(
        stable=re.search(rb"\nstable_bundle=([0-9a-f]{64})\n", body)[1],
        bundle=re.search(rb"\nbundle=([0-9a-f]{64})\n", body)[1],
        stable_epoch=int(re.search(rb"\nstable_epoch=([0-9]+)\n", body)[1]),
        candidate_epoch=int(re.search(rb"\ncandidate_epoch=([0-9]+)\n", body)[1]),
        transaction=re.search(rb"\ntransaction=([0-9a-f-]{36})\n", body)[1],
    )
    with tempfile.TemporaryDirectory(prefix="disposable-", dir=args.output) as directory:
        work = Path(directory)
        members = [work / f"member-{side}.raw" for side in ("a", "b")]
        for member in members:
            subprocess.run(["cp", "--reflink=auto", "--sparse=always", args.lab / member.name, member], check=True)
        depot, digest = provision_depot(args, work, trial)
        install(args, work, members, depot)
        depot.unlink()
        options = SimpleNamespace(disk=args.disk, runtime=None, guest=False, output=args.output, variables=args.variables,
                                  nvme_boot=True, boot_sector_size=4096, no_default_devices=True,
                                  memory_mib=4096, persistent_members=True)
        commit = b"FVCA_GUEST_TRIAL_COMMITTED " + trial.transaction + b" 1 " + trial.bundle
        status_end = b'"security_deadline_missed":false}'
        finish = status_end if args.routine else commit
        log = harness["boot"](args, options, members, storage, "scheduled", finish, 270)
        assert b"FVCA_GUEST_OS_UPDATE_TIMER_ENROLLED" in log
        assert b'"staged":"' + digest + b'"' in log
        if args.routine:
            assert b'"disposition":"outside-maintenance"' in log
            assert log.count(b"FVCA_SERVICE_GUEST_READY") == 1
            assert b"FVCA_SERVICE_GUEST_STOPPED" not in log and b"FVCA_GUEST_TRIAL_ATTEMPT " not in log
        else:
            assert log.count(b"FVCA_GUEST_TRIAL_ATTEMPT ") == 1
            assert log.count(b"FVCA_SERVICE_GUEST_READY") == 2
            assert commit in log
            cold = harness["boot"](args, options, members, storage, "cold", b'"disposition":"current"', 240)
            assert b"FVCA_GUEST_RELEASE_SELECTED " + trial.bundle in cold and b"FVCA_GUEST_TRIAL_ATTEMPT " not in cold
            assert b'"manifest_sha256":"' + digest + b'"' in cold
    print("Scheduled Guest staging deferred disruption" if args.routine else "Scheduled Guest update committed and reconciled after a cold boot")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("disk", "candidate", "lab", "approval", "trial-key", "owner-key", "firmware", "variables", "kernel", "output"):
        parser.add_argument(f"--{name}", required=True, type=lambda value: Path(value).resolve())
    parser.add_argument("--routine", action="store_true")
    args = parser.parse_args()
    args.output.mkdir(mode=0o700)
    qualify(args)
