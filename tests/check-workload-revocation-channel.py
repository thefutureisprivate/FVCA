#!/usr/bin/env python3
"""Exercise the Guest channel entry point with signed notices on a private Btrfs bind mount."""

import argparse
import base64
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import tempfile
import time

from tuf.api.metadata import TargetFile


TESTS = Path(__file__).resolve().parent
TOOLS = TESTS.parent / "tools"
HEAD = "fvca-workload.guest-test.test.stable.json"


def run(args, root, fixture, cms):
    tuf = runpy.run_path(str(TESTS / "check-release-intake.py"))
    https = runpy.run_path(str(TESTS / "check-release-https.py"))
    root.mkdir(mode=0o700)
    now = int(time.time())
    grant, candidate = fixture.prepare_transition()
    scope, _, active = fixture.unsigned(request={"expires": now + 2400})
    source = json.loads((fixture.bundle / "source-evidence.json").read_bytes())
    issuer = root / "issued"
    issuer.mkdir(mode=0o700)
    for name, field in (("permit.json", "permit"), ("permit.p7s", "signature"), ("source-policy.json", "policy")):
        (issuer / name).write_bytes(base64.b64decode(source[field], validate=True))
    shutil.copyfile(fixture.bundle / "launch.json", issuer / "launch.json")
    shutil.copyfile(fixture.permit_authority.with_suffix(".crt"), issuer / "authority.crt")
    candidate_scope, _, offered = fixture.unsigned(bundle=candidate, request={"expires": now + 2400})
    grant.update(from_authorization=active, to_authorization=offered, to_source_policy=candidate_scope["source_policy"],
                 expires=now + 1200)
    transition = root / "transition"
    transition.mkdir(mode=0o700)
    shutil.move(candidate, transition / "candidate")
    cms["write"](transition / "transition.json", grant)
    cms["sign"](transition / "transition.json", fixture.deploy)
    publication = root / "publication"
    subprocess.run([
        "python3", "-B", "-W", "error", TOOLS / "pack-workload-offer.py", "--verifier", args.verifier,
        "--channel", "stable", "--sequence", "1", "--valid-from", str(now - 60), "--expires", str(now + 1200),
        "--current-policy", fixture.policy, "--current", fixture.bundle,
        "--deployment-certificate", fixture.deploy.with_suffix(".crt"),
        "--workload-certificate", fixture.workload.with_suffix(".crt"),
        "--transition", transition, "--output", publication,
    ], check=True)
    head = json.loads((publication / HEAD).read_bytes())
    updates = {file.name: file for file in publication.iterdir()}

    def sign_notice(name, action, reason):
        output = root / name
        subprocess.run([
            "python3", "-B", "-W", "error", TOOLS / "revoke-workload-permit.py", "--permit", issuer,
            "--authority-key", fixture.permit_authority.with_suffix(".key"), "--action", action,
            "--reason", reason, "--channel", "stable", "--output", output,
        ], check=True)
        return next(output.iterdir())

    block = sign_notice("block", "block-new-starts", "Fence this reviewed deployment")
    stop = sign_notice("stop", "stop", "Stop this reviewed deployment")
    conflict = sign_notice("conflict", "block-new-starts", "Another reason for the same immutable slot")
    keys = tuf["new_keys"]()
    stamp = datetime.now(UTC)

    def repository(name, version, files, *, omit_image=False):
        directory = root / name
        targets = directory / "targets"
        targets.mkdir(parents=True)
        entries = {name: TargetFile.from_file(name, str(path), ["sha256"]) for name, path in files.items()}
        for name, path in files.items():
            if not (omit_image and name.endswith("-workload.raw")):
                os.link(path, targets / f"{entries[name].hashes['sha256']}.{name}")
        tuf["publish"](directory, (1, version), keys, stamp, entries)
        return directory

    first = repository("first", 2, updates | {block.name: block}, omit_image=True)
    initial_root = first / "metadata/1.root.json"
    runtime = root / "runtime"
    data = root / "guest-data"
    trust = runtime / "fvca/workload-trust"
    image = runtime / "fvca/workload-image"
    for directory in (data, data / "workload-updates", runtime, trust, image, runtime / "fvca-workload-channel"):
        directory.mkdir(parents=True, mode=0o700)
    shutil.copytree(fixture.bundle, data / "workload")
    cms["write"](trust / "policy.json", scope)
    for signer, name in ((fixture.deploy, "deployment.der"), (fixture.workload, "verity.der")):
        (trust / name).write_bytes(cms["openssl"]("x509", "-in", signer.with_suffix(".crt"), "-outform", "DER"))
    shutil.copyfile(initial_root, trust / "channel-root.json")
    depot = trust / "channel-depot.json"
    policy = {
        "schema": "fvca-workload-channel-policy-v1", "guest": "guest-test", "service": "test", "channel": "stable",
        "tuf_root_sha256": hashlib.sha256(initial_root.read_bytes()).hexdigest(), "max_artifact_bytes": 660 * 1024**2,
    }
    (image / "authorization").write_text(active + "\n", encoding="ascii")
    lease = runtime / "fvca/workload-lifecycle.lock"
    lease.touch(mode=0o600)
    role = root / "role"
    role.write_text("service-guest\n", encoding="ascii")

    def update(repo, case, error=None, *, server=None, ca=None):
        if server is None:
            mounts = ["--network=none", "-v", f"{repo}:/repository:ro"]
            config = {"transport": "local", "path": "/repository"}
        else:
            mounts = ["--network=host", "-v", f"{ca}:/channel-ca.pem:ro"]
            config = {"transport": "https", "base_url": f"https://127.0.0.1:{server.server_port}/fvca/depot/",
                      "ca_file": "/channel-ca.pem", "deadline_seconds": 30}
        depot.write_text(json.dumps(config), encoding="ascii")
        cms["write"](trust / "channel-policy.json", policy | {"depot_config_sha256": hashlib.sha256(depot.read_bytes()).hexdigest()})
        result = subprocess.run([
            "podman", "run", "--rm", "--pull=never", "--user", "0", "--security-opt=label=disable", *mounts,
            "-v", f"{runtime}:/run:rw", "-v", f"{data}:/run/fvca/guest-data:rw", "-v", f"{role}:/usr/lib/fvca/role:ro",
            "-v", f"{args.client}:/fvca-channel:ro", args.builder_image, "/fvca-channel",
        ], check=False, capture_output=True, text=True)
        if result.returncode != (1 if error else 0) or (error and error not in result.stderr):
            raise RuntimeError(f"{case} failed\n{result.stdout}{result.stderr}")
        if (runtime / "fvca-workload-channel/ready.json").exists() or (data / "workload-updates/incoming").exists():
            raise ValueError(f"{case} unexpectedly authorized an update")
        if (data / "workload-updates/.channel-download").exists():
            raise ValueError(f"{case} retained the temporary channel spool")
        print(f"{case} passed", flush=True)
        return result.stdout

    ledger = data / "workload-updates/permit-revocations"
    block_leaf = ledger / block.name.removeprefix("fvca-permit.guest-test.test.stable.")
    stop_leaf = ledger / stop.name.removeprefix("fvca-permit.guest-test.test.stable.")

    def retained(path, original):
        if path.stat().st_mode & 0o777 != 0o400 or path.read_bytes() != original.read_bytes():
            raise ValueError(f"permit notice differs from the signed target: {path}")

    with tempfile.TemporaryDirectory(prefix=".channel-tls-", dir=root) as tls:
        ca, _, authority = https["certificate"](Path(tls), "permit-channel-ca")
        leaf, key, _ = https["certificate"](Path(tls), "127.0.0.1", authority=authority)
        with https["serve"](first, (leaf, key)) as server:
            update(first, "https-revocation-before-update", "unsigned workload permit is revoked", server=server, ca=ca)
            if not any(path.endswith(block.name) for path in server.requests) or any(
                path.endswith("-workload.raw") for path in server.requests
            ):
                raise ValueError("the channel requested an unexpected HTTPS target")
    retained(block_leaf, block)
    expired = root / "expired-head.json"
    cms["write"](expired, head | {"sequence": 2, "valid_from": now - 120, "expires": now - 1, "release": None})
    update(repository("stop-with-expired-head", 3, {HEAD: expired, stop.name: stop}),
           "stop-despite-expired-workload-head", "invalid or expired workload channel head")
    retained(stop_leaf, stop)
    withdrawal = root / "withdrawal.json"
    cms["write"](withdrawal, head | {"sequence": 3, "release": None})
    interrupted = ledger / ".channel-revocation.new"
    interrupted.write_text("previous incomplete notice", encoding="ascii")
    update(repository("without-notices", 4, {HEAD: withdrawal}), "omission-keeps-revocations")
    if interrupted.exists():
        raise ValueError("interrupted notice survived refresh after its target was withdrawn")
    retained(block_leaf, block)
    retained(stop_leaf, stop)
    repeated = repository("with-identical-notices", 5, {HEAD: withdrawal, block.name: block, stop.name: stop})
    if "FVCA_WORKLOAD_PERMIT_NOTICE_RETAINED" in update(repeated, "retry-is-idempotent"):
        raise ValueError("re-imported an existing notice")
    update(repository("conflicting-notice", 6, {HEAD: withdrawal, conflict.name: conflict}),
           "reject-notice-replacement", "conflicting content for an immutable permit revocation notice")
    retained(block_leaf, block)
    update(repository("incorrect-action", 7, {HEAD: withdrawal, stop.name: block}),
           "reject-renamed-notice", "revocation target name differs from its signed permit and action")
    update(repository("invalid-envelope", 8, {HEAD: withdrawal, block.name: issuer / "permit.json"}),
           "reject-invalid-envelope", "unknown field")
    wrong_authority = root / "wrong-authority.json"
    body = json.loads(block.read_bytes())
    body["authority"] = base64.b64encode((trust / "verity.der").read_bytes()).decode("ascii")
    cms["write"](wrong_authority, body)
    update(repository("invalid-issuer", 9, {HEAD: withdrawal, block.name: wrong_authority}),
           "reject-wrong-issuer", "matching the Guest enrollment")
    retained(stop_leaf, stop)
    if sorted(path.name for path in ledger.iterdir()) != sorted((block_leaf.name, stop_leaf.name)):
        raise ValueError("revocation receipt set contains unexpected files")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("client", "verifier", "output"):
        parser.add_argument(f"--{name}", type=lambda path: Path(path).absolute(), required=True)
    parser.add_argument("--builder-image", required=True)
    args = parser.parse_args()
    cms = runpy.run_path(str(TESTS / "check-workload-admission.py"))
    admission = cms["Admission"]
    admission.setUpClass()
    fixture = admission()
    try:
        fixture.setUp()
        run(args, args.output, fixture, cms)
    finally:
        fixture.doCleanups()
        admission.doClassCleanups()


if __name__ == "__main__":
    main()
