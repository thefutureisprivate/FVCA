#!/usr/bin/env python3
"""Qualify threshold verification, root rotation and atomic depot publication."""

import argparse
from datetime import UTC, datetime, timedelta
import fcntl
import json
import os
from pathlib import Path
import runpy
import shutil
import signal
import subprocess
import sys
import tempfile

from tuf.api.metadata import Metadata, Root, TargetFile


PUBLISHER = Path(__file__).resolve().parents[1] / "tools/tuf-depot.py"
INTAKE = runpy.run_path(str(Path(__file__).with_name("check-release-intake.py")))
HTTPS = runpy.run_path(str(Path(__file__).with_name("check-release-https.py")))


def invoke(arguments, *, expected=None):
    result = subprocess.run(arguments, capture_output=True, timeout=180, check=False)
    if expected is None:
        assert result.returncode == 0, result.stderr.decode()
    else:
        assert result.returncode != 0 and expected in result.stderr.decode(), result.stderr.decode()
    return result.stdout


def command(*arguments):
    return [sys.executable, "-B", "-W", "error", PUBLISHER, *arguments]


def package_args(packages):
    return [argument for package in packages for argument in ("--package", package)]


def root_bytes(keys, now, version, previous=None):
    root = Root(version=version, expires=now + timedelta(days=90), consistent_snapshot=True)
    for name, signers in keys.items():
        for signer in signers:
            root.add_key(signer.public_key, name)
    root.roles["root"].threshold = 2
    older = previous["root"] if previous else []
    return INTAKE["sign"](root, [*older, *keys["root"]])


def signed_roles(output, packages, root, keys, now, versions):
    output.mkdir()
    for (role, validity), version in zip((("targets", 31), ("snapshot", 3), ("timestamp", .5)), versions, strict=True):
        expiry = int((now + timedelta(days=validity)).timestamp())
        if role == "targets":
            extras = package_args(packages)
        else:
            predecessor = "targets" if role == "snapshot" else "snapshot"
            extras = ["--input", output / f"{predecessor}.json", "--trusted-root", root]
        draft = invoke(command(f"draft-{role}", "--version", str(version), "--expires", str(expiry), *extras))
        document = Metadata.from_bytes(draft)
        assert not document.signatures
        for signer in keys[role]:
            document.sign(signer, append=True)
        (output / f"{role}.json").write_bytes(document.to_bytes())


def publish(depot, trusted_root, signed, packages):
    return command("publish", "--depot", depot, "--trusted-root", trusted_root,
                   "--signed", signed, *package_args(packages))


def make_package(work, name, marker, epoch):
    package = work / name
    targets = package / "targets"
    targets.mkdir(parents=True)
    raw = package / "guest-input.raw"
    raw.write_bytes(marker * 4096)
    qualification = package / "qualification.json"
    INTAKE["write_json"](qualification, {"fixture": name})
    selection, sources = INTAKE["make_release"](package, {"guest-boot.raw": raw, "qualification.json": qualification},
                                                 epoch, "service-guest")
    references = {}
    for name, source in sources.items():
        target = TargetFile.from_file(name, str(source), ["sha256"])
        (targets / f"{target.hashes['sha256']}.{name}").hardlink_to(source)
        references[name] = target.to_dict()
    INTAKE["write_json"](package / "target-records.json", references)
    INTAKE["write_json"](package / "selection.json", selection)
    return package


def kill_publisher(work, arguments, *, after_exchange):
    tools = work / "interrupt"
    tools.mkdir(exist_ok=True)
    shim = tools / "mv"
    line = "subprocess.run(['/usr/bin/mv', *sys.argv[1:]], check=True)\n" if after_exchange else ""
    shim.write_text(f"#!{sys.executable}\nimport os, signal, subprocess, sys\n{line}"
                    "os.kill(os.getppid(), signal.SIGKILL)\n")
    shim.chmod(0o700)
    env = os.environ | {"PATH": f"{tools}:{os.environ['PATH']}"}
    result = subprocess.run(arguments, env=env, capture_output=True, timeout=30, check=False)
    assert result.returncode == -signal.SIGKILL, result.stderr.decode()


def qualify(client, work):
    now = datetime.now(UTC).replace(microsecond=0)
    keys = INTAKE["new_keys"]()
    pin = work / "trusted-root.json"
    pin.write_bytes(root_bytes(keys, now, 1))
    old = make_package(work, "prior", b"a", 7)
    candidate = make_package(work, "candidate", b"b", 8)
    depot = work / "depot"
    state = work / "state"
    state.mkdir(mode=0o700)
    config = work / "depot.json"
    INTAKE["write_json"](config, {"transport": "local", "path": str(depot)})
    first = work / "first"
    signed_roles(first, [old], pin, keys, now, (1, 1, 1))
    invoke(publish(depot, pin, first, [old]))
    assert invoke([client, pin, config, state, old / "selection.json"]).startswith(b"FVCA_RELEASE_STAGED ")
    first_timestamp = (depot / "metadata/timestamp.json").read_bytes()
    previous_index = (depot / "metadata/1.targets.json").read_bytes()
    previous_names = sorted(path.name for path in (depot / "targets").iterdir())
    print("initial publication and Rust intake passed", flush=True)

    second = work / "second"
    signed_roles(second, [candidate], pin, keys, now, (2, 2, 2))
    update = publish(depot, pin, second, [candidate])
    with (work / ".depot.publish.lock").open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        invoke(update, expected="Resource temporarily unavailable")
    timestamp_path = depot / "metadata/timestamp.json"
    new_target = next((candidate / "targets").glob("*guest-boot.raw"))
    original = new_target.read_bytes()
    new_target.write_bytes(b"c" * len(original))
    invoke(update, expected="Observed hash")
    assert timestamp_path.read_bytes() == first_timestamp and not (depot / "metadata/2.targets.json").exists()
    new_target.write_bytes(original)

    abandoned = work / ".depot.publish"
    kill_publisher(work, update, after_exchange=False)
    assert abandoned.is_dir() and timestamp_path.read_bytes() == first_timestamp
    kill_publisher(work, update, after_exchange=True)
    assert abandoned.is_dir() and timestamp_path.read_bytes() == (second / "timestamp.json").read_bytes()
    assert (depot / "metadata/1.targets.json").read_bytes() == previous_index
    for filename in previous_names:
        assert (depot / "targets" / filename).read_bytes() == (old / "targets" / filename).read_bytes()
    invoke(update)
    assert not abandoned.exists() and invoke([client, pin, config, state, candidate / "selection.json"]).startswith(
        b"FVCA_RELEASE_STAGED "
    )
    print("concurrent-writer rejection, corrupt-target refusal and interruption on both sides of exchange passed",
          flush=True)

    second_timestamp = timestamp_path.read_bytes()
    invoke(publish(depot, pin, first, []), expected="would roll the published depot back")
    conflict = work / "same-version"
    signed_roles(conflict, [old, candidate], pin, keys, now, (2, 3, 3))
    invoke(publish(depot, pin, conflict, []), expected="changes an already published version")
    unsigned = Metadata.from_bytes((second / "timestamp.json").read_bytes())
    unsigned.sign(keys["snapshot"][0])
    incorrect = work / "wrong-authority"
    shutil.copytree(second, incorrect)
    (incorrect / "timestamp.json").write_bytes(unsigned.to_bytes())
    invoke(publish(depot, pin, incorrect, []), expected="timestamp was signed by")
    too_late = str(int((now + timedelta(days=2)).timestamp()))
    invoke(command("draft-timestamp", "--version", "3", "--expires", too_late,
                   "--input", second / "snapshot.json", "--trusted-root", pin), expected="expiry is outside")
    assert timestamp_path.read_bytes() == second_timestamp
    print("rollback, same-version substitution, wrong-role signatures and invalid expiry rejected", flush=True)

    refresh = work / "timestamp-only"
    shutil.copytree(second, refresh)
    expires = str(int((now + timedelta(hours=20)).timestamp()))
    draft = invoke(command("draft-timestamp", "--version", "3", "--expires", expires,
                           "--input", refresh / "snapshot.json", "--trusted-root", pin))
    timestamp = Metadata.from_bytes(draft)
    timestamp.sign(keys["timestamp"][0])
    (refresh / "timestamp.json").write_bytes(timestamp.to_bytes())
    invoke(publish(depot, pin, refresh, []))
    assert timestamp_path.read_bytes() == (refresh / "timestamp.json").read_bytes()
    assert (depot / "metadata/2.targets.json").read_bytes() == (second / "targets.json").read_bytes()
    assert (depot / "metadata/2.snapshot.json").read_bytes() == (second / "snapshot.json").read_bytes()
    print("timestamp-only renewal preserved the existing snapshot and offline targets signatures", flush=True)

    next_keys = INTAKE["new_keys"]()
    next_root = work / "next-root.json"
    next_root.write_bytes(root_bytes(next_keys, now, 2, keys))
    third = work / "third"
    signed_roles(third, [old, candidate], next_root, next_keys, now, (3, 3, 4))
    incoming_root = third / "2.root.json"
    incoming_root.write_bytes(root_bytes(next_keys, now, 2))
    invoke(publish(depot, pin, third, []), expected="root was signed by")
    assert not (depot / "metadata/2.root.json").exists()
    assert timestamp_path.read_bytes() == (refresh / "timestamp.json").read_bytes()
    incoming_root.write_bytes(next_root.read_bytes())
    rotated = publish(depot, pin, third, [])
    kill_publisher(work, rotated, after_exchange=True)
    assert (depot / "metadata/1.root.json").read_bytes() == pin.read_bytes()
    assert (depot / "metadata/2.root.json").read_bytes() == next_root.read_bytes()
    assert invoke([client, pin, config, state, old / "selection.json"]).startswith(b"FVCA_RELEASE_STAGED ")
    invoke(rotated)
    assert not abandoned.exists()
    print("dual-threshold root rotation and Rust intake with existing trusted state passed", flush=True)

    ca, _, authority = HTTPS["certificate"](work, "fvca-publication-ca")
    leaf, secret, _ = HTTPS["certificate"](work, "127.0.0.1", authority)
    https_state = work / "https-state"
    https_state.mkdir(mode=0o700)
    with HTTPS["serve"](depot, (leaf, secret)) as origin:
        host, port = origin.server_address
        INTAKE["write_json"](config, {"transport": "https", "base_url": f"https://{host}:{port}{HTTPS['PREFIX']}",
                                     "ca_file": str(ca), "deadline_seconds": 30})
        assert invoke([client, pin, config, https_state, candidate / "selection.json"]).startswith(
            b"FVCA_RELEASE_STAGED "
        )
        assert any(path.endswith("/metadata/2.root.json") for path in origin.requests)
        assert any(path.endswith("guest-boot.raw") for path in origin.requests)
    print("published depot served rotated metadata and exact targets over TLS", flush=True)


def qualify_retirement(client, work):
    now = datetime.now(UTC).replace(microsecond=0)
    keys = INTAKE["new_keys"]()
    expired = make_package(work, "expired", b"a", 7)
    draining = make_package(work, "draining", b"b", 8)
    fallback = make_package(work, "fallback", b"c", 9)
    current = make_package(work, "current", b"d", 10)
    depot = work / "depot"
    depot.mkdir()
    live_targets = depot / "targets"
    live_targets.mkdir()

    def legacy_view(directory, version, published, packages):
        targets = {}
        for package in packages:
            records = json.loads((package / "target-records.json").read_bytes())
            targets.update({name: TargetFile.from_dict(record, name) for name, record in records.items()})
        INTAKE["publish"](directory, (1, version), keys, published, targets)
        for package in packages:
            for source in (package / "targets").iterdir():
                target = live_targets / source.name
                if not target.exists():
                    target.hardlink_to(source)

    legacy_view(depot, 1, now - timedelta(days=7), [expired, fallback])
    previous = work / "previous"
    previous.mkdir()
    legacy_view(previous, 2, now - timedelta(days=4, minutes=5), [draining, fallback])
    metadata = depot / "metadata"
    for name in ("2.snapshot.json", "2.targets.json", "timestamp.json"):
        (previous / "metadata" / name).replace(metadata / name)
    pin = work / "trusted-root.json"
    shutil.copyfile(metadata / "1.root.json", pin)

    next_keys = INTAKE["new_keys"]()
    next_root = work / "next-root.json"
    next_root.write_bytes(root_bytes(next_keys, now, 2, keys))
    signed = work / "signed"
    signed_roles(signed, [fallback, current], next_root, next_keys, now, (3, 3, 3))
    shutil.copyfile(next_root, signed / "2.root.json")
    updated = publish(depot, pin, signed, [current]) + ["--max-clock-skew-seconds", "900"]
    expiry = int((now + timedelta(minutes=10)).timestamp())
    assert f"metadata=2 targets=3 next_expiry={expiry}".encode() in invoke(updated)
    assert not (metadata / "1.snapshot.json").exists() and not (metadata / "1.targets.json").exists()
    assert (metadata / "2.snapshot.json").is_file() and (metadata / "2.targets.json").is_file()

    def published_objects():
        return {path.name for path in live_targets.iterdir()}

    def names(*packages):
        return {file.name for package in packages for file in (package / "targets").iterdir()}

    assert published_objects() == names(draining, fallback, current)
    print("publication retired only expired exclusive targets and retained the clock-skew drain window", flush=True)

    prune = command("prune", "--depot", depot, "--trusted-root", pin, "--max-clock-skew-seconds", "0")
    kept_timestamp = (metadata / "timestamp.json").read_bytes()
    archived_snapshot = metadata / "2.snapshot.json"
    original = archived_snapshot.read_bytes()
    changed = Metadata.from_bytes(original)
    changed.signed.expires -= timedelta(days=7)
    archived_snapshot.write_bytes(changed.to_bytes())
    invoke(prune, expected="historical snapshot 2 has no verified signing root")
    assert published_objects() == names(draining, fallback, current)
    archived_snapshot.write_bytes(original)

    fallback_object = live_targets / next(iter(names(fallback)))
    detached = work / "temporary-fallback"
    fallback_object.rename(detached)
    invoke(prune, expected="required by a retained view")
    detached.rename(fallback_object)
    kill_publisher(work, prune, after_exchange=False)
    assert published_objects() == names(draining, fallback, current)
    assert b"metadata=2 targets=3 next_expiry=none" in invoke(prune)
    assert published_objects() == names(fallback, current)
    assert (metadata / "timestamp.json").read_bytes() == kept_timestamp
    assert (metadata / "1.root.json").read_bytes() == pin.read_bytes()
    assert (metadata / "2.root.json").read_bytes() == next_root.read_bytes()
    assert b"metadata=0 targets=0 next_expiry=none" in invoke(prune)

    config = work / "depot.json"
    INTAKE["write_json"](config, {"transport": "local", "path": str(depot)})
    state = work / "state"
    state.mkdir(mode=0o700)
    for package in (current, fallback):
        assert invoke([client, pin, config, state, package / "selection.json"]).startswith(b"FVCA_RELEASE_STAGED ")
    print("retirement rejected tampered history and missing pins, recovered from interruption and staged the fallback",
          flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", type=lambda path: Path(path).absolute(), required=True)
    parser.add_argument("--scratch-directory", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="fvca-tuf-depot-", dir=args.scratch_directory) as directory:
        qualify(args.client, Path(directory).absolute())
    with tempfile.TemporaryDirectory(prefix="fvca-tuf-retirement-", dir=args.scratch_directory) as directory:
        qualify_retirement(args.client, Path(directory).absolute())


if __name__ == "__main__":
    main()
