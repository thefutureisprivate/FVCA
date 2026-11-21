#!/usr/bin/env python3
"""Qualify reviewed Host and Guest release packages with reference TUF and the Rust client."""

import argparse
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile

from securesystemslib.signer import CryptoSigner
from tuf.api.metadata import TargetFile


ROOT = Path(__file__).resolve().parent.parent
GUEST_INVENTORY = "service-guest-boot-inventory.json"
HOST_INVENTORY = "hypervisor-boot-inventory.json"
INTAKE = runpy.run_path(str(Path(__file__).with_name("check-release-intake.py")))


def record(path):
    return {"bytes": path.stat().st_size, "sha256": INTAKE["sha256"](path)}


def invoke(command, expected=None):
    result = subprocess.run(command, capture_output=True, text=True, timeout=180, check=False)
    if expected is None:
        assert result.returncode == 0, result.stderr
    else:
        assert result.returncode and expected in result.stderr, result.stderr
    return result.stdout


def package(args, scratch, role):
    names = ["guest-boot.raw"]
    evidence_names = [GUEST_INVENTORY]
    if role == "hypervisor":
        names += ["boot.raw", "vm-runtime.raw"]
        evidence_names.append(HOST_INVENTORY)
    evidence = scratch / "review-evidence"
    evidence.mkdir()
    for name in evidence_names:
        (evidence / name).hardlink_to(args.evidence_directory / name)
    (evidence / "qualification.log").write_text("Disposable development qualification for release intake\n")
    review = {
        "schema": "fvca-os-release-review-v1", "role": role, "epoch": 19,
        "artifacts": {name: record(args.artifact_directory / name) for name in names},
        "evidence": {path.name: record(path) for path in evidence.iterdir()},
    }
    review_file = scratch / "approved-review.json"
    digest = INTAKE["write_json"](review_file, review)
    command = [sys.executable, "-B", "-W", "error", ROOT / "tools/pack-os-release.py",
               "--artifact-directory", args.artifact_directory, "--evidence-directory", evidence,
               "--review", review_file, "--minimum-epoch", "18"]
    if role == "hypervisor":
        command += ["--vm-runtime-certificate", args.vm_runtime_certificate]
    prepared = scratch / "prepared"
    invoke(command + ["--review-sha256", digest, "--output", prepared])

    def reject(reason, name, pin):
        destination = scratch / name
        invoke(command + ["--review-sha256", pin, "--output", destination], reason)
        assert not destination.exists() and not list(scratch.glob(".fvca-os-release-*"))
        print(f"{role} {name} rejected", flush=True)

    reject("differs from the independently approved digest", "unapproved-review", "0" * 64)
    # Simulate a review whose digest is approved but whose asserted artifact is not the image on disk.
    guest = review["artifacts"]["guest-boot.raw"]
    original_digest = guest["sha256"]
    guest["sha256"] = "1" * 64
    reject("artifact differs from the qualification review", "replaced-artifact",
           INTAKE["write_json"](review_file, review))
    guest["sha256"] = original_digest

    if role == "hypervisor":
        # An approved inventory can still describe a Guest other than the one in this Host slot.
        path = evidence / GUEST_INVENTORY
        document = json.loads(path.read_bytes())
        document["capsule_image"]["verity_root"] = "2" * 64
        path.unlink()
        INTAKE["write_json"](path, document)
        review["evidence"][GUEST_INVENTORY] = record(path)
        reject("detached Guest boot differs from the embedded Guest", "mixed-composition",
               INTAKE["write_json"](review_file, review))
    return prepared, {*names, "release.json", "qualification.json"}


def qualify(args, scratch, role):
    prepared, names = package(args, scratch, role)
    selected = json.loads((prepared / "selection.json").read_bytes())
    stem = INTAKE["target_prefix"](selected)
    depot = scratch / "depot"
    depot.mkdir()
    (prepared / "targets").rename(depot / "targets")
    targets = {name: TargetFile.from_dict(member, name) for name, member in
               json.loads((prepared / "target-records.json").read_bytes()).items()}
    assert targets.keys() == {f"{stem}-{name}" for name in names}
    assert selected["max_release_bytes"] == sum(target.length for target in targets.values())
    for name, target in targets.items():
        payload = depot / "targets" / f"{target.hashes['sha256']}.{name}"
        with payload.open("rb") as file:
            target.verify_length_and_hashes(file)

    now = datetime.now(UTC).replace(microsecond=0)
    stamp = int(now.timestamp())
    owner, qualification = (CryptoSigner.generate_ed25519() for _ in range(2))
    compatibility = "3" * 64
    head = f"fvca-os-{role}-stable"
    head_bytes = INTAKE["encode_json"]({
        "schema": "fvca-os-channel-v1", "role": role, "channel": "stable", "sequence": 2,
        "valid_from": stamp - 60, "expires": stamp + 600, "compatibility_sha256": compatibility,
        "release": {"epoch": selected["epoch"], "manifest_sha256": selected["manifest_sha256"],
                    "activation": {"urgency": "security", "activate_by": stamp + 300}},
    })
    proof = bytes.fromhex(qualification.sign(head_bytes).signature)
    for name, data in ((head + ".json", head_bytes), (head + ".sig", proof)):
        member = TargetFile.from_data(name, data, ["sha256"])
        (depot / "targets" / f"{member.hashes['sha256']}.{name}").write_bytes(data)
        targets[name] = member
    INTAKE["publish"](depot, (1, 1), INTAKE["new_keys"](), now, targets)
    trusted = depot / "metadata/1.root.json"
    config, policy, signature, key = (
        scratch / name for name in ("depot.json", "policy.json", "policy.sig", "owner.public")
    )
    depot_digest = INTAKE["write_json"](config, {"transport": "local", "path": str(depot)})
    INTAKE["write_json"](policy, {
        "schema": "fvca-os-update-policy-v1", "revision": 1, "role": role, "channel": "stable", "enabled": True,
        "valid_from": stamp - 60, "expires": stamp + 600, "tuf_root_sha256": INTAKE["sha256"](trusted),
        "depot_config_sha256": depot_digest, "qualification_key_ed25519": qualification.public_key.keyval["public"],
        "compatibility_sha256": compatibility, "minimum_epoch": selected["minimum_epoch"],
        "max_release_bytes": selected["max_release_bytes"], "max_staged_bytes": selected["max_release_bytes"],
    })
    signature.write_bytes(bytes.fromhex(owner.sign(policy.read_bytes()).signature))
    key.write_bytes(bytes.fromhex(owner.public_key.keyval["public"]))
    state = scratch / "state"
    state.mkdir(mode=0o700)
    placement = {"slot": "a"} if role == "hypervisor" else {"guest_bundle": "4" * 64}
    INTAKE["write_json"](state / "active-os-release.json", placement | {
        "role": role, "epoch": 18, "sequence": 1, "manifest_sha256": "5" * 64,
    })
    command = [args.client, "--discover-os-release", trusted, config, state, policy, signature, key]
    result = json.loads(invoke(command))
    assert result["disposition"] == "ready" and result["staged"] == selected["manifest_sha256"], result
    retry = invoke([args.client, trusted, config, state, prepared / "selection.json"])
    assert retry.startswith("FVCA_RELEASE_STAGED "), retry
    installed = state / "staged" / selected["manifest_sha256"]
    assert {path.name for path in installed.iterdir()} == names
    for name in sorted(names):
        expected = targets[f"{stem}-{name}"]
        assert record(installed / name) == {"bytes": expected.length, "sha256": expected.hashes["sha256"]}
    print(f"{role} signed TUF discovery and exact staging passed: {selected['manifest_sha256']}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("client", "artifact-directory", "evidence-directory", "vm-runtime-certificate", "scratch-directory"):
        parser.add_argument(f"--{name}", type=lambda value: Path(value).absolute(), required=True)
    args = parser.parse_args()
    os.umask(0o077)
    for role in ("hypervisor", "service-guest"):
        with tempfile.TemporaryDirectory(prefix=f"fvca-{role}-publisher-", dir=args.scratch_directory) as directory:
            qualify(args, Path(directory), role)


if __name__ == "__main__":
    main()
