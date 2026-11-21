#!/usr/bin/env python3
"""Qualify exact workload delivery with independent TUF and CMS signers."""

import argparse
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import time

from tuf.api.metadata import TargetFile


TESTS = Path(__file__).resolve().parent


def check(args, fixture, cms):
    tuf = runpy.run_path(str(TESTS / "check-release-intake.py"))
    https = runpy.run_path(str(TESTS / "check-release-https.py"))
    root = args.output
    root.mkdir(mode=0o700)
    now = int(time.time())
    grant, candidate = fixture.prepare_transition()
    grant["expires"] = now + 3600
    transition = root / "transition"
    transition.mkdir(mode=0o700)
    shutil.move(candidate, transition / "candidate")
    cms["write"](transition / "transition.json", grant)
    cms["sign"](transition / "transition.json", fixture.deploy)
    targets = root / "publication"
    subprocess.run([
        "python3", TESTS.parent / "tools/pack-workload-offer.py",
        "--verifier", args.verifier, "--channel", "stable", "--sequence", "2",
        "--valid-from", str(now - 60), "--expires", str(now + 1800),
        "--current-policy", fixture.policy, "--current", fixture.bundle,
        "--deployment-certificate", fixture.deploy.with_suffix(".crt"),
        "--workload-certificate", fixture.workload.with_suffix(".crt"),
        "--transition", transition, "--output", targets,
    ], check=True)

    trust = root / "trust"
    trust.mkdir(mode=0o700)
    shutil.copyfile(fixture.policy, trust / "policy.json")
    for signer, name in ((fixture.deploy, "deployment.der"), (fixture.workload, "verity.der")):
        (trust / name).write_bytes(cms["openssl"]("x509", "-in", signer.with_suffix(".crt"), "-outform", "DER"))
    keys = tuf["new_keys"]()
    published_at = datetime.now(UTC)
    head_name = "fvca-workload.guest-test.test.stable.json"
    head = json.loads((targets / head_name).read_bytes())
    raw = next(targets.glob("*-workload.raw"))
    proof = next(targets.glob("*-transition.p7s"))
    sources = {file.name: file for file in targets.iterdir()}

    def repository(name, version, replacements=None, remove_image=False):
        directory = root / name
        members = directory / "targets"
        members.mkdir(parents=True)
        selected = sources | (replacements or {})
        index = {key: TargetFile.from_file(key, str(file), ["sha256"]) for key, file in selected.items()}
        for key, file in selected.items():
            if key != raw.name or not remove_image:
                os.link(file, members / f"{index[key].hashes['sha256']}.{key}")
        tuf["publish"](directory, (1, version), keys, published_at, index)
        return directory

    first = repository("valid-depot", 2)
    initial_root = first / "metadata/1.root.json"
    fingerprint = hashlib.sha256(initial_root.read_bytes()).hexdigest()

    def intake(name, config, state_path=None, expected=None, selected=True):
        config_path = root / f"{name}-depot.json"
        config_path.write_text(json.dumps(config), encoding="ascii")
        policy = root / f"{name}-policy.json"
        policy.write_text(json.dumps({
            "schema": "fvca-workload-channel-policy-v1", "guest": "guest-test", "service": "test",
            "channel": "stable", "tuf_root_sha256": fingerprint, "max_artifact_bytes": 660 * 1024**2,
            "depot_config_sha256": hashlib.sha256(config_path.read_bytes()).hexdigest(),
        }), encoding="ascii")
        directory = state_path or root / f"{name}-state"
        directory.mkdir(mode=0o700, exist_ok=True)
        output = root / f"{name}-incoming"
        result = subprocess.run([
            args.client, "--prepare", policy, initial_root, config_path, trust, fixture.bundle, directory, output,
        ], capture_output=True, text=True, check=False)
        if expected:
            if result.returncode != 1 or expected not in result.stderr or output.exists():
                raise ValueError(f"{name} gave unexpected output {result.stdout} {result.stderr}")
        elif selected:
            if result.returncode or "FVCA_WORKLOAD_CHANNEL_DELIVERED" not in result.stdout:
                raise ValueError(f"{name} failed to deliver the signed transition {result.stderr}")
            original = {path.relative_to(transition): tuf["sha256"](path)
                        for path in transition.rglob("*") if path.is_file()}
            delivered = {path.relative_to(output): tuf["sha256"](path)
                         for path in output.rglob("*") if path.is_file()}
            if original != delivered:
                raise ValueError("published inbox does not match the exact authorized transition")
        elif result.returncode or output.exists() or "NO_ELIGIBLE_OFFER" not in result.stdout:
            raise ValueError(f"{name} did not preserve the current selection {result.stderr}")
        print(f"{name} passed", flush=True)
        return directory

    def local(directory):
        return {"transport": "local", "path": str(directory)}

    state = intake("signed-local", local(first))
    lower = root / "old-head.json"
    lower.write_text(json.dumps(head | {"sequence": 1}), encoding="ascii")
    rollback = repository("rollback-depot", 3, {head_name: lower})
    intake("reject-channel-rollback", local(rollback), state, "rollback or conflicting sequence")
    withdrawal = root / "withdrawn.json"
    withdrawal.write_text(json.dumps(head | {"sequence": 3, "release": None}), encoding="ascii")
    intake("signed-withdrawal", local(repository("withdrawn-depot", 4, {head_name: withdrawal})), state, selected=False)
    conflict = root / "conflict.json"
    conflict.write_text(json.dumps(head | {"sequence": 3}), encoding="ascii")
    intake("reject-conflicting-sequence", local(repository("conflict-depot", 5, {head_name: conflict})),
           state, "rollback or conflicting sequence")

    ca, _, issuer = https["certificate"](root, "workload-lab-ca")
    cert, key, _ = https["certificate"](root, "localhost", authority=issuer)

    def fetch(name, directory, expected=None):
        with https["serve"](directory, (cert, key)) as server:
            intake(name, {"transport": "https", "base_url": f"https://localhost:{server.server_port}/fvca/depot/",
                          "ca_file": str(ca), "deadline_seconds": 30}, expected=expected)
            reads_image = any(path.endswith("-workload.raw") for path in server.requests)
            if reads_image != (expected is None):
                raise ValueError(f"{name} requested the raw artifact at the wrong stage")

    fetch("signed-https", first)
    invalid_signature = root / "invalid.p7s"
    invalid_signature.write_bytes(proof.read_bytes()[:-1] + bytes([proof.read_bytes()[-1] ^ 1]))
    fetch("reject-grant-before-artifact",
          repository("invalid-proof-depot", 2, {proof.name: invalid_signature}, remove_image=True),
          "CMS")
    wrong_disk = root / "wrong.raw"
    wrong_disk.write_bytes(bytes([raw.read_bytes()[0] ^ 1]) + raw.read_bytes()[1:])
    fetch("reject-tuf-artifact-before-download",
          repository("wrong-image-depot", 2, {raw.name: wrong_disk}, remove_image=True),
          "TUF target digest or length differs")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ("client", "verifier", "output"):
        parser.add_argument(f"--{arg}", required=True, type=lambda path: Path(path).absolute())
    args = parser.parse_args()
    cms = runpy.run_path(str(TESTS / "check-workload-admission.py"))
    admission = cms["Admission"]
    admission.setUpClass()
    fixture = admission()
    try:
        fixture.setUp()
        check(args, fixture, cms)
    finally:
        fixture.doCleanups()
        admission.doClassCleanups()


if __name__ == "__main__":
    main()
