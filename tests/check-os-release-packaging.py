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
from uuid import uuid4

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
    targets = {name: TargetFile.from_dict(member, name) for name, member in
               json.loads((prepared / "target-records.json").read_bytes()).items()}
    assert targets.keys() == {f"{stem}-{name}" for name in names}
    assert selected["max_release_bytes"] == sum(target.length for target in targets.values())
    for name, target in targets.items():
        payload = prepared / "targets" / f"{target.hashes['sha256']}.{name}"
        with payload.open("rb") as file:
            target.verify_length_and_hashes(file)

    now = datetime.now(UTC).replace(microsecond=0)
    stamp = int(now.timestamp())
    owner, qualification, trial = (CryptoSigner.generate_ed25519() for _ in range(3))
    compatibility = "3" * 64
    keys = INTAKE["new_keys"]()
    initial = scratch / "initial"
    initial.mkdir()
    INTAKE["publish"](initial, (1, 1), keys, now, {})
    scope = scratch / "scope"
    scope.mkdir(mode=0o700)
    trusted, policy, signature, key = (scope / name for name in
                                      ("trusted-root.json", "policy.json", "policy.sig", "owner.public"))
    (initial / "metadata/1.root.json").rename(trusted)
    config = scratch / "depot.json"
    depot_digest = INTAKE["write_json"](config, {"transport": "local", "path": str(depot)})
    standing = {
        "schema": "fvca-os-update-policy-v1", "revision": 1, "role": role, "channel": "stable", "enabled": True,
        "valid_from": stamp - 60, "expires": stamp + 600, "tuf_root_sha256": INTAKE["sha256"](trusted),
        "depot_config_sha256": depot_digest, "qualification_key_ed25519": qualification.public_key.keyval["public"],
        "compatibility_sha256": compatibility, "minimum_epoch": selected["minimum_epoch"],
        "max_release_bytes": selected["max_release_bytes"], "max_staged_bytes": selected["max_release_bytes"],
    }
    if role == "service-guest":
        standing["trial_key_ed25519"] = trial.public_key.keyval["public"]
    INTAKE["write_json"](policy, standing)
    signature.write_bytes(bytes.fromhex(owner.sign(policy.read_bytes()).signature))
    key.write_bytes(bytes.fromhex(owner.public_key.keyval["public"]))
    state = scratch / "state"
    state.mkdir(mode=0o700)
    placement = {"slot": "a"} if role == "hypervisor" else {"guest_bundle": "4" * 64}
    INTAKE["write_json"](scope / "active-os-release.json", placement | {
        "role": role, "epoch": 18, "sequence": 1, "manifest_sha256": "5" * 64,
    })
    (state / "active-os-release.json").hardlink_to(scope / "active-os-release.json")
    approvals = scratch / "approvals"
    approvals.mkdir()
    request = scratch / "request.json"
    document = {
        "sequence": 2, "valid_from": stamp - 60, "expires": stamp + 600,
        "release": {"manifest_sha256": selected["manifest_sha256"],
                    "activation": {"urgency": "security", "activate_by": stamp + 300}},
    }
    INTAKE["write_json"](request, document)
    author_args = [scope, request, prepared, approvals]
    draft = [args.client, "--prepare-os-channel", *author_args]
    if role == "service-guest":
        inventory = json.loads((args.evidence_directory / GUEST_INVENTORY).read_bytes())
        release = inventory["guest_release"]
        bundle = inventory["capsule_image"]["verity_root"]
        image = targets[f"{stem}-guest-boot.raw"]
        launch = (f"FVCA-GUEST-LAUNCH-1\nbundle={bundle}\ncore={release['core_root']}\n"
                  f"runtime={release['runtime_root']}\n")
        for name in ("boot.efi", "linux", "initrd", "cmdline", "domain.xml", "core.raw", "runtime.raw"):
            launch += f"{release['files'][name]}  {name}\n"
        launch += f"{release['release_sha256']}  release.json\n{release['signature_sha256']}  release.p7s\n"
        body = (f"FVCA-GUEST-TRIAL-1\ntransaction={uuid4()}\nguest=e629aa43-af11-47c6-aedc-a2dc47f1cc3a\n"
                f"stable_bundle={placement['guest_bundle']}\nstable_epoch=18\ncandidate_epoch={selected['epoch']}\n"
                f"not_before={stamp-60}\nexpires={stamp+600}\nhealth_seconds=45\ndata=compatible\n"
                f"candidate_image_sha256={image.hashes['sha256']}\ncandidate_image_bytes={image.length}\n{launch}")
        packet = approvals / "guest-trial.bin"
        changed = body.replace(f"bundle={bundle}\n", f"bundle={'6' * 64}\n").encode()
        packet.write_bytes(bytes.fromhex(trial.sign(changed).signature) + changed)
        invoke(draft, "packed Guest verity root differs from the qualified trial")
        print("service-guest independently signed wrong launch root rejected", flush=True)
        body = body.encode()
        packet.write_bytes(bytes.fromhex(trial.sign(body).signature) + body)

    head_bytes = invoke(draft).encode()
    head = json.loads(head_bytes)
    assert head["role"] == role and head["compatibility_sha256"] == compatibility
    if role == "service-guest":
        assert head["release"]["trial_approval"] == record(approvals / "guest-trial.bin")
    proof = scratch / "qualification.sig"
    packaged_channel = scratch / "channel"
    seal = [args.client, "--pack-os-channel", *author_args, proof, packaged_channel]
    if role == "service-guest":
        proof.write_bytes(bytes.fromhex(owner.sign(head_bytes).signature))
        invoke(seal, "invalid independent channel qualification signature")
        assert not packaged_channel.exists()
        print("service-guest wrong qualification authority rejected", flush=True)
    proof.write_bytes(bytes.fromhex(qualification.sign(head_bytes).signature))
    invoke(seal)
    (prepared / "targets").rename(depot / "targets")
    for name, member in json.loads((packaged_channel / "target-records.json").read_bytes()).items():
        target = TargetFile.from_dict(member, name)
        filename = f"{target.hashes['sha256']}.{name}"
        (packaged_channel / "targets" / filename).rename(depot / "targets" / filename)
        targets[name] = target
    INTAKE["publish"](depot, (1, 1), keys, now, targets)
    assert trusted.read_bytes() == (depot / "metadata/1.root.json").read_bytes()
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
    print(f"{role} independently authored channel and exact staging passed: {selected['manifest_sha256']}", flush=True)
    if role == "service-guest":
        INTAKE["write_json"](request, document | {"sequence": 3, "release": None})
        withdrawal = json.loads(invoke(draft))
        assert withdrawal["release"] is None and withdrawal["sequence"] == 3
        print("service-guest explicit withdrawal authored", flush=True)


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
