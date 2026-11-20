#!/usr/bin/env python3
"""Exercise standing OS update policy against independently signed TUF channel targets."""

import argparse
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess

from securesystemslib.signer import CryptoSigner
from tuf.api.metadata import TargetFile


intake = runpy.run_path(Path(__file__).with_name("check-release-intake.py"))


def signed(path, document, signer):
    intake["write_json"](path, document)
    return signature(path, signer)


def signature(path, signer):
    output = path.with_suffix(".sig")
    output.write_bytes(bytes.fromhex(signer.sign(path.read_bytes()).signature))
    return output


def qualify(client, output):
    output.mkdir(mode=0o700)
    now = datetime.now(UTC).replace(microsecond=0)
    stamp = int(now.timestamp())
    owner, gate = (CryptoSigner.generate_ed25519() for _ in range(2))
    key = output / "owner.public"
    key.write_bytes(bytes.fromhex(owner.public_key.keyval["public"]))
    root_keys = intake["new_keys"]()
    repo = output / "depot"
    repo.mkdir()
    (repo / "targets").mkdir()
    config = output / "depot.json"
    config_digest = intake["write_json"](config, {"transport": "local", "path": str(repo)})
    trusted = output / "trusted-root.json"
    policy_file = output / "policy.json"
    seq = 0
    sources = {}

    def make_release(role, label):
        work = output / label
        work.mkdir()
        payloads = {}
        names = ("guest-boot.raw", "qualification.json")
        if role == "hypervisor":
            names += ("boot.raw", "vm-runtime.raw")
        for name in names:
            payloads[name] = work / name
            intake["write_json"](payloads[name], {"test": name, "fixture": label})
        selection, targets = intake["make_release"](work, payloads, 7, role)
        sources.update(targets)
        return selection

    stable, next_host, active_guest, next_guest = (
        make_release(role, label) for role, label in
        (("hypervisor", "host-one"), ("hypervisor", "host-two"),
         ("service-guest", "guest-one"), ("service-guest", "guest-two"))
    )
    active_digest = stable["manifest_sha256"]
    compatibility = "a" * 64

    def state(name, role="hypervisor"):
        path = output / name
        path.mkdir(mode=0o700)
        active = active_digest if role == "hypervisor" else active_guest["manifest_sha256"]
        intake["write_json"](path / "active-os-release.json",
                             {"role": role, "epoch": 7, "manifest_sha256": active, "sequence": 1})
        return path

    def head(selection, sequence, *, security=None, role="hypervisor", **overrides):
        release = None
        if selection is not None:
            activation = {"urgency": "routine"} if security is None else {"urgency": "security", "activate_by": security}
            release = {k: selection[k] for k in ("epoch", "manifest_sha256")} | {"activation": activation}
        return {"schema": "fvca-os-channel-v1", "role": role, "channel": "stable", "sequence": sequence,
                "valid_from": stamp - 3600, "expires": stamp + 3600, "release": release,
                "compatibility_sha256": compatibility} | overrides

    def publish(document, signer=gate, role="hypervisor"):
        nonlocal seq
        seq += 1
        revision = output / f"tuf-{seq}"
        revision.mkdir()
        pointer = revision / f"fvca-os-{role}-stable.json"
        proof = signed(pointer, document, signer)
        targets = {}
        for name, path in (sources | {pointer.name: pointer, proof.name: proof}).items():
            reference = TargetFile.from_file(name, str(path), ["sha256"])
            target = repo / "targets" / f"{reference.hashes['sha256']}.{name}"
            if not target.exists():
                os.link(path, target)
            targets[name] = reference
        intake["publish"](revision, (1, seq), root_keys, now, targets)
        if not trusted.exists():
            shutil.copyfile(revision / "metadata/1.root.json", trusted)
        shutil.copytree(revision / "metadata", repo / "metadata", dirs_exist_ok=True)

    # Place the signed routine window an hour away so this test is independent of local time.
    start = (now.hour * 60 + now.minute + 60) % 1440
    policy = {
        "schema": "fvca-os-update-policy-v1", "revision": 1, "role": "hypervisor", "channel": "stable",
        "enabled": True, "valid_from": stamp - 3600, "expires": stamp + 3600,
        "depot_config_sha256": config_digest, "qualification_key_ed25519": gate.public_key.keyval["public"],
        "compatibility_sha256": compatibility, "minimum_epoch": 7, "max_release_bytes": 65536,
        "max_staged_bytes": 131072, "maintenance": {"timezone": "UTC", "start_minute": start,
                                                      "end_minute": (start + 30) % 1440},
    }
    live = state("live")
    publish(head(next_host, 2))
    policy["tuf_root_sha256"] = intake["sha256"](trusted)

    def discover(name, expected, *, directory=live, settings=policy, error=False):
        proof = signed(policy_file, settings, gate if name == "unsigned-owner" else owner)
        result = subprocess.run(
            [client, "--discover-os-release", trusted, config, directory, policy_file, proof, key],
            capture_output=True, text=True, timeout=20, check=False,
        )
        (output / f"{name}.log").write_text(result.stdout + result.stderr)
        if error:
            intake["require"](result.returncode != 0 and expected in result.stderr, f"{name}: {result}")
            response = {}
        else:
            intake["require"](result.returncode == 0, f"{name}: {result}")
            response = json.loads(result.stdout)
            persisted = json.loads((directory / "os-update-status.json").read_bytes())
            intake["require"](response == persisted and response["disposition"] == expected, f"{name}: {response}")
        print(f"{name} passed", flush=True)
        return response

    receipt = discover("routine-outside-window", "outside-maintenance")
    candidate = next_host["manifest_sha256"]
    assert receipt["staged"] == candidate and receipt["active"]["manifest_sha256"] == active_digest
    assert stamp <= receipt["last_refresh"] < receipt["fresh_until"] <= stamp + 3600
    stage = live / "staged" / candidate
    prefix = intake["target_prefix"](next_host) + "-"
    assert {path.name: intake["sha256"](path) for path in stage.iterdir()} == {
        name.removeprefix(prefix): intake["sha256"](path) for name, path in sources.items() if name.startswith(prefix)
    }
    discover("retry-staged", "outside-maintenance")
    discover("unsigned-owner", "invalid standing OS update policy signature", error=True)
    discover("different-depot", "differs from standing OS update policy",
             settings=policy | {"depot_config_sha256": "b" * 64}, error=True)

    hold = {"manifest_sha256": candidate, "until": stamp + 600}
    bounded = policy | {"revision": 2, "hold": hold}
    publish(head(next_host, 3, security=stamp + 300))
    receipt = discover("security-release-held", "hold", settings=bounded)
    assert receipt["hold_until"] == stamp + 300 and not receipt["security_deadline_missed"]
    publish(head(next_host, 4, security=stamp - 1))
    receipt = discover("security-deadline-bypasses-hold-and-window", "ready", settings=bounded)
    assert receipt["hold_until"] is None and receipt["security_deadline_missed"]
    discover("replayed-policy", "sequence rollback", error=True)

    publish(head(next_host, 3, security=stamp + 300))
    discover("replayed-channel-with-fresh-tuf-metadata", "sequence rollback", settings=bounded, error=True)
    publish(head(stable, 4))
    discover("channel-sequence-equivocation", "sequence rollback or equivocation", settings=bounded, error=True)
    publish(head(next_host, 5), signer=root_keys["targets"][0])
    discover("tuf-alone-cannot-qualify", "invalid independent channel qualification signature", settings=bounded,
             error=True)
    publish(head(next_host, 5, compatibility_sha256="b" * 64))
    discover("wrong-compatibility", "outside standing policy scope", settings=bounded, error=True)
    publish(head(next_host, 5, expires=stamp - 2))
    discover("expired-channel", "expired or outside standing policy scope", settings=bounded, error=True)
    publish(head(stable, 5))
    assert discover("already-active", "current", settings=bounded)["staged"] is None
    publish(head(None, 6))
    assert discover("signed-empty-channel", "no-release", settings=bounded)["candidate"] is None
    discover("signed-disabled", "disabled", settings=policy | {"revision": 3, "enabled": False})

    full = state("full")
    (full / "staged").mkdir(mode=0o700)
    retained = full / "staged" / active_digest
    retained.mkdir(mode=0o700)
    (retained / "retained.raw").write_bytes(b"x" * 1024)
    publish(head(next_host, 7))
    discover("quota-preserves-retained-tuple", "staging quota is exhausted", directory=full,
             settings=policy | {"max_release_bytes": 1024, "max_staged_bytes": 1024}, error=True)
    assert list((full / "staged").iterdir()) == [retained]

    guest = state("guest", "service-guest")
    guest_policy = policy | {"role": "service-guest"}
    publish(head(next_guest, 2, security=stamp + 300, role="service-guest"), role="service-guest")
    receipt = discover("service-guest-release", "ready", directory=guest, settings=guest_policy)
    assert receipt["staged"] == next_guest["manifest_sha256"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", type=lambda value: Path(value).absolute(), required=True)
    parser.add_argument("--output", type=lambda value: Path(value).absolute(), required=True)
    args = parser.parse_args()
    os.umask(0o077)
    qualify(args.client, args.output)
