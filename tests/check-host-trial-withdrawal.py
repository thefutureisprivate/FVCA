#!/usr/bin/env python3
"""Exercise signed withdrawal of a queued Host approval on a disposable Btrfs mount."""

import argparse
from datetime import UTC, datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess

from securesystemslib.signer import CryptoSigner
from tuf.api.metadata import TargetFile


HERE = Path(__file__).parent
intake = runpy.run_path(HERE / "check-release-intake.py")
signed = runpy.run_path(HERE / "check-release-channel.py")["signed"]
BOOT = Path("/run/fvca")
POOL = BOOT / "host-data"
ORIGIN = "user.fvca.channel-origin"
STABLE_ESP = "11111111-1111-4111-8111-111111111111"
CANDIDATE_ESP = "22222222-2222-4222-8222-222222222222"
TRANSACTION = "33333333-3333-4333-8333-333333333333"


def trial_envelope(signer, stamp, root, epoch_policy, transaction):
    core_a, core_b, runtime_a, runtime_b, guest_a, guest_b = (
        f"11111111-1111-4111-8111-11111111111{i}" for i in range(2, 8)
    )
    body = (
        f"FVCA-HYPERVISOR-STANDING-TRIAL-2\nnot_before={stamp-60}\nexpires={stamp+1800}\n"
        f"stable_epoch=1\ncandidate_epoch=2\nepoch_policy_sha256={epoch_policy}\n"
        f"stable_core={root}\nstable_runtime={root}\nstable_guest_bundle={root}\n"
        f"candidate_uki_sha256={root}\ncandidate_uki_bytes=2048\n"
        f"candidate_core_devices={core_a},{core_b}\ncandidate_runtime_devices={runtime_a},{runtime_b}\n"
        f"candidate_guest_devices={guest_a},{guest_b}\n"
        f"FVCA-HYPERVISOR-TRIAL-2\ntransaction={transaction}\n"
        f"stable=000a,{STABLE_ESP}\ncandidate=000b,{CANDIDATE_ESP}\n"
        f"candidate_esp_sha256={root}\ncandidate_esp_bytes=4096\n"
        f"candidate_core={root}\ncandidate_runtime={root}\nguest_bundle={root}\n"
    ).encode("ascii")
    return bytes.fromhex(signer.sign(body).signature) + body


def qualify(client, output):
    if os.geteuid() != 0 or not POOL.is_mount() or any(POOL.iterdir()) or any(BOOT.glob("*-owner")):
        raise ValueError("use an isolated runtime root and empty disposable Host data mount")
    output.mkdir(mode=0o700)
    directory, inbox = POOL / "os-update", POOL / "boot-trials"
    for path in (directory, inbox):
        path.mkdir(mode=0o700)
    depot = directory / "depot"
    (depot / "targets").mkdir(parents=True)
    owner, qualifier, trial = (CryptoSigner.generate_ed25519() for _ in range(3))
    keys = intake["new_keys"]()
    trial_key = trial.public_key.keyval["public"]
    stable, candidate, root, epoch_policy, compatibility = (letter * 64 for letter in "abcde")
    now = datetime.now(UTC).replace(microsecond=0)
    stamp = int(now.timestamp())
    packet = trial_envelope(trial, stamp, root, epoch_policy, TRANSACTION)
    old = inbox / "pending-trial"
    retired = inbox / f"{TRANSACTION}.withdrawn"
    (BOOT / "os-update-owner").write_bytes(bytes.fromhex(owner.public_key.keyval["public"]))
    (BOOT / "os-update-depot").write_text("local\n")
    context_file = BOOT / "running-trial-context"
    context = (bytes.fromhex(trial_key)
        + f"{STABLE_ESP}\n{root}\n{root}\n{root}\nfvca.hypervisor_epoch=1,{epoch_policy}\n".encode()
    )
    context_file.write_bytes(context)
    lease = BOOT / "guest-capture.lock"
    lease.touch(mode=0o600)
    active = {"role": "hypervisor", "slot": "a", "epoch": 1, "sequence": 1, "manifest_sha256": stable}
    intake["write_json"](directory / "active-os-release.json", active)
    config_digest = intake["write_json"](
        directory / "depot.json", {"transport": "local", "path": str(depot)}
    )

    def publish(metadata_version, qualifier_key):
        revision = output / f"tuf-{metadata_version}"
        revision.mkdir()
        head = revision / "fvca-os-hypervisor-stable.json"
        proof = signed(head, {
            "schema": "fvca-os-channel-v1", "role": "hypervisor", "channel": "stable", "sequence": 3,
            "valid_from": stamp - 60, "expires": stamp + 1800, "compatibility_sha256": compatibility,
            "release": None,
        }, qualifier_key)
        targets = {}
        for path in (head, proof):
            target = TargetFile.from_file(path.name, str(path), ["sha256"])
            destination = depot / "targets" / f"{target.hashes['sha256']}.{path.name}"
            shutil.copyfile(path, destination)
            targets[path.name] = target
        intake["publish"](revision, (1, metadata_version), keys, now, targets)
        shutil.copytree(revision / "metadata", depot / "metadata", dirs_exist_ok=True)

    publish(1, owner)
    anchor = directory / "trusted-root.json"
    shutil.copyfile(depot / "metadata/1.root.json", anchor)
    signed(directory / "policy.json", {
        "schema": "fvca-os-update-policy-v1", "revision": 1, "role": "hypervisor", "channel": "stable",
        "enabled": True, "valid_from": stamp - 60, "expires": stamp + 1800, "minimum_epoch": 1,
        "tuf_root_sha256": intake["sha256"](anchor), "depot_config_sha256": config_digest,
        "qualification_key_ed25519": qualifier.public_key.keyval["public"],
        "compatibility_sha256": compatibility, "trial_key_ed25519": trial_key,
        "max_release_bytes": 32768, "max_staged_bytes": 65536,
        "hypervisor_gpt": {"sector_size": 4096, "boot_certificate": "/disposable/certificate.pem",
                           "boot_certificate_sha256": root, "epoch_policy_sha256": epoch_policy,
                           "storage_policy_sha256": root, "storage_pcr_key_fingerprint": root,
                           "a": {"path": "/disposable/slot-a", "gpt_sha256": root},
                           "b": {"path": "/disposable/slot-b", "gpt_sha256": root}},
    }, owner)

    def run(label, error=None):
        result = subprocess.run([client, "--run-host-update"], capture_output=True, text=True, timeout=30)
        (output / f"{label}.log").write_text(result.stdout + result.stderr)
        if error is None:
            assert result.returncode == 0, result
            status = json.loads(result.stdout.splitlines()[-1])
            assert status["disposition"] == "no-release" and status["active"] == active
        else:
            assert result.returncode != 0 and error in result.stderr, result
        print(f"{label} passed", flush=True)

    old.write_bytes(packet)
    os.setxattr(old, ORIGIN, json.dumps({
        "channel": "stable", "sequence": 2, "stable_manifest": stable, "candidate_manifest": candidate,
        "trial": {"bytes": len(packet), "sha256": hashlib.sha256(packet).hexdigest()},
    }).encode())
    original = old.stat().st_ino
    run("unqualified-withdrawal", "invalid independent channel qualification signature")
    assert old.read_bytes() == packet

    publish(2, qualifier)
    with lease.open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        run("lease-busy", "operation would block")
        assert old.stat().st_ino == original and not retired.exists()

    context_file.write_bytes(context.replace(STABLE_ESP.encode(), CANDIDATE_ESP.encode()))
    run("different-running-release", "trial does not authorize the running stable composition")
    assert old.stat().st_ino == original and not retired.exists()
    context_file.write_bytes(context)

    reservation = inbox / TRANSACTION
    reservation.write_bytes(packet)
    run("reserved-trial-preserved")
    assert old.stat().st_ino == original and not retired.exists()
    reservation.unlink()

    run("withdrawal")
    assert not old.exists() and retired.stat().st_ino == original and retired.read_bytes() == packet
    run("identical-withdrawal")
    independent = trial_envelope(trial, stamp, root, epoch_policy, "44444444-4444-4444-8444-444444444444")
    old.write_bytes(independent)
    run("independent-approval-preserved")
    assert old.read_bytes() == independent and retired.read_bytes() == packet


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    qualify(args.client.absolute(), args.output.absolute())
