#!/usr/bin/env python3
"""Qualify Host download retirement through the scheduled Btrfs update command."""

import argparse
from datetime import UTC, datetime
import fcntl
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess

from securesystemslib.signer import CryptoSigner
from tuf.api.metadata import TargetFile


fixture = runpy.run_path(Path(__file__).with_name("check-host-trial-withdrawal.py"))
BOOT, POOL = fixture["BOOT"], fixture["POOL"]
intake, signed = fixture["intake"], fixture["signed"]
ORIGIN = "user.fvca.host-download"
MEMBERS = ("boot.raw", "vm-runtime.raw", "guest-boot.raw", "qualification.json")


def qualify(client, output):
    if os.geteuid() != 0 or not POOL.is_mount() or any(POOL.iterdir()) or any(BOOT.glob("*-owner")):
        raise ValueError("use an isolated runtime root and empty disposable Host data mount")
    output.mkdir(mode=0o700)
    state = POOL / "os-update"
    staged = state / "staged"
    inbox = POOL / "boot-trials"
    depot = state / "depot"
    staged.mkdir(mode=0o700, parents=True)
    inbox.mkdir(mode=0o700)
    (depot / "targets").mkdir(parents=True)
    owner, qualifier, trial = (CryptoSigner.generate_ed25519() for _ in range(3))
    keys = intake["new_keys"]()
    now = datetime.now(UTC).replace(microsecond=0)
    stamp = int(now.timestamp())
    owner_file = BOOT / "os-update-owner"
    owner_file.write_bytes(bytes.fromhex(owner.public_key.keyval["public"]))
    (BOOT / "os-update-depot").write_text("local\n")
    lease = BOOT / "guest-capture.lock"
    lease.touch(mode=0o600)
    config = state / "depot.json"
    config_digest = intake["write_json"](config, {"transport": "local", "path": str(depot)})
    anchor, policy = state / "trusted-root.json", state / "policy.json"
    root, epoch_policy, compatibility = (letter * 64 for letter in "abc")
    trial_key = trial.public_key.keyval["public"]
    context = BOOT / "running-trial-context"
    context.write_bytes(bytes.fromhex(trial_key) + (
        f"{fixture['STABLE_ESP']}\n{root}\n{root}\n{root}\nfvca.hypervisor_epoch=1,{epoch_policy}\n"
    ).encode())
    sources = {}

    def release(label, epoch):
        work = output / label
        work.mkdir()
        payloads = {name: work / name for name in MEMBERS}
        for name, path in payloads.items():
            path.write_bytes(f"{label}/{name}\n".encode() * 256)
        selection, targets = intake["make_release"](work, payloads, epoch, "hypervisor")
        sources.update(targets)
        return selection

    stable, promoted, independent, first, second = (
        release(label, epoch) for label, epoch in (
            ("stable", 1), ("promoted", 2), ("independent", 3), ("first", 3), ("second", 3)
        )
    )

    def digest(selection):
        return selection["manifest_sha256"]

    def stage(selection):
        return staged / digest(selection)

    def seed(selection, managed):
        destination = stage(selection)
        destination.mkdir(mode=0o700)
        prefix = intake["target_prefix"](selection) + "-"
        for name in (*MEMBERS, "release.json"):
            target = destination / name
            shutil.copyfile(sources[prefix + name], target)
            target.chmod(0o400)
        if managed:
            os.setxattr(destination, ORIGIN, digest(selection).encode())

    seed(stable, True)
    seed(independent, False)
    active_file = state / "active-os-release.json"
    active = {"role": "hypervisor", "slot": "a", "epoch": 1, "sequence": 1, "manifest_sha256": digest(stable)}
    intake["write_json"](active_file, active)
    checkpoint = state / "recovery-os-release.json"

    def publish(version, sequence, selection, signer=qualifier):
        revision = output / f"head-{version}"
        revision.mkdir()
        pointer = revision / "fvca-os-hypervisor-stable.json"
        offer = None if selection is None else {
            "epoch": selection["epoch"], "manifest_sha256": digest(selection), "activation": {"urgency": "routine"},
        }
        proof = signed(pointer, {
            "schema": "fvca-os-channel-v1", "role": "hypervisor", "channel": "stable", "sequence": sequence,
            "valid_from": stamp - 60, "expires": stamp + 1800, "compatibility_sha256": compatibility,
            "release": offer,
        }, signer)
        targets = {}
        for name, path in (sources | {pointer.name: pointer, proof.name: proof}).items():
            target = TargetFile.from_file(name, str(path), ["sha256"])
            destination = depot / "targets" / f"{target.hashes['sha256']}.{name}"
            if not destination.exists():
                shutil.copyfile(path, destination)
            targets[name] = target
        intake["publish"](revision, (1, version), keys, now, targets)
        shutil.copytree(revision / "metadata", depot / "metadata", dirs_exist_ok=True)

    publish(1, 2, promoted)
    shutil.copyfile(depot / "metadata/1.root.json", anchor)
    start = (now.hour * 60 + now.minute + 60) % 1440
    # Only one supersedable download fits alongside the three retained tuples.
    protected_bytes = sum(item["max_release_bytes"] for item in (stable, promoted, independent))
    one_download = max(item["max_release_bytes"] for item in (first, second))
    proof = signed(policy, {
        "schema": "fvca-os-update-policy-v1", "revision": 1, "role": "hypervisor", "channel": "stable",
        "enabled": True, "valid_from": stamp - 60, "expires": stamp + 1800, "minimum_epoch": 1,
        "tuf_root_sha256": intake["sha256"](anchor), "depot_config_sha256": config_digest,
        "qualification_key_ed25519": qualifier.public_key.keyval["public"],
        "compatibility_sha256": compatibility, "trial_key_ed25519": trial_key,
        "max_release_bytes": max(protected["max_release_bytes"]
                                 for protected in (stable, promoted, independent, first, second)),
        "max_staged_bytes": protected_bytes + one_download,
        "maintenance": {"timezone": "UTC", "start_minute": start, "end_minute": (start + 30) % 1440},
        "hypervisor_gpt": {"sector_size": 4096, "boot_certificate": "/disposable/certificate.pem",
                           "boot_certificate_sha256": root, "epoch_policy_sha256": epoch_policy,
                           "storage_policy_sha256": root, "storage_pcr_key_fingerprint": root,
                           "a": {"path": "/disposable/slot-a", "gpt_sha256": root},
                           "b": {"path": "/disposable/slot-b", "gpt_sha256": root}},
    }, owner)

    def run(label, expected=None, *, error=None, manual=False):
        arguments = (
            ["--discover-os-release", anchor, config, state, policy, proof, owner_file]
            if manual else ["--run-host-update"]
        )
        result = subprocess.run([client, *arguments], capture_output=True, text=True, timeout=30)
        (output / f"{label}.log").write_text(result.stdout + result.stderr)
        if error:
            assert result.returncode != 0 and error in result.stderr, result
        else:
            assert result.returncode == 0, result
            status = json.loads(result.stdout.splitlines()[-1])
            assert status["disposition"] == ("outside-maintenance" if expected else "no-release"), status
            assert status["staged"] == (digest(expected) if expected else None), status
        print(f"{label} passed", flush=True)

    run("scheduled-download", promoted)
    assert os.getxattr(stage(promoted), ORIGIN) == digest(promoted).encode()

    # Represent the verified initrd result consumed by the release client.
    packet = fixture["trial_envelope"](trial, stamp, root, epoch_policy, fixture["TRANSACTION"])
    promotion = BOOT / "promoted-os-release"
    promotion.write_bytes((
        "FVCA-HYPERVISOR-STANDING-PROMOTION-2\nstable_slot=a\nstable_sequence=1\ncandidate_sequence=2\n"
        f"stable_manifest_sha256={digest(stable)}\ncandidate_manifest_sha256={digest(promoted)}\n"
    ).encode() + packet[64:])
    publish(2, 3, first)
    run("promotion-pins-recovery", first)
    assert json.loads(checkpoint.read_bytes()) == active
    assert json.loads(active_file.read_bytes()) == dict(
        active, slot="b", epoch=2, sequence=2, manifest_sha256=digest(promoted)
    )
    promotion.unlink()
    context.write_bytes(context.read_bytes()
                        .replace(fixture["STABLE_ESP"].encode(), fixture["CANDIDATE_ESP"].encode())
                        .replace(b"hypervisor_epoch=1,", b"hypervisor_epoch=2,"))
    retained = {stage(item) for item in (stable, promoted, independent)}
    assert set(staged.iterdir()) == retained | {stage(first)}

    publish(3, 4, second, owner)
    run("unqualified-supersession", error="invalid independent channel qualification signature")
    assert stage(first).exists() and not stage(second).exists()
    publish(4, 4, second)
    with lease.open("rb") as locked:
        fcntl.flock(locked, fcntl.LOCK_EX)
        run("busy-lease", error="operation would block")
        assert stage(first).exists()
    run("reclaim-before-quota", second)
    assert set(staged.iterdir()) == retained | {stage(second)}

    publish(5, 5, None)
    pending = inbox / "pending-trial"
    pending.write_bytes(packet)
    run("queued-trial-defers-retirement")
    assert stage(second).exists()
    pending.unlink()
    run("withdrawal-retires-download")
    assert set(staged.iterdir()) == retained

    # An interruption can leave a detached or unpublished directory.
    seed(second, True)
    detached = staged / f".retired-{digest(second)}"
    stage(second).rename(detached)
    (detached / "release.json").unlink()
    partial = staged / ".stage-interrupted"
    partial.mkdir(mode=0o700)
    os.setxattr(partial, ORIGIN, digest(second).encode())
    (partial / "release.json").touch(mode=0o400)
    publish(6, 6, second)
    run("resume-retirement-and-redownload", second)
    assert set(staged.iterdir()) == retained | {stage(second)}

    run("independent-adoption", second, manual=True)
    assert ORIGIN not in os.listxattr(stage(second))
    publish(7, 7, None)
    run("independent-tuple-preserved")
    assert set(staged.iterdir()) == retained | {stage(second)}

    next_trial = packet[64:].replace(b"stable_epoch=1\ncandidate_epoch=2\n",
                                     b"stable_epoch=2\ncandidate_epoch=3\n")
    promotion.write_bytes((
        "FVCA-HYPERVISOR-STANDING-PROMOTION-2\nstable_slot=b\nstable_sequence=2\ncandidate_sequence=8\n"
        f"stable_manifest_sha256={digest(promoted)}\ncandidate_manifest_sha256={digest(second)}\n"
    ).encode() + next_trial)
    publish(8, 8, None)
    run("next-promotion-retires-former-peer")
    assert set(staged.iterdir()) == {stage(item) for item in (promoted, independent, second)}
    assert json.loads(checkpoint.read_bytes())["manifest_sha256"] == digest(promoted)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    qualify(args.client.absolute(), args.output.absolute())
