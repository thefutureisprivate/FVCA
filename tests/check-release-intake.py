#!/usr/bin/env python3
"""Exercise the Rust intake against repositories signed by the TUF reference implementation."""

import argparse
from datetime import UTC, datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

from securesystemslib.signer import CryptoSigner
from tuf.api.metadata import MetaFile, Metadata, Root, Snapshot, TargetFile, Targets, Timestamp


def require(condition, message):
    if not condition:
        raise ValueError(message)


def encode_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def write_json(path, obj):
    data = encode_json(obj)
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def sign(role, signers):
    metadata = Metadata(role)
    for signer in signers:
        metadata.sign(signer, append=True)
    return metadata.to_bytes()


def new_keys():
    counts = {"root": 2, "targets": 1, "snapshot": 1, "timestamp": 1}
    return {role: [CryptoSigner.generate_ed25519() for _ in range(count)] for role, count in counts.items()}


def publish(path, versions, keys, now, targets, previous=None, expired=False):
    metadata = path / "metadata"
    metadata.mkdir()
    root_version, release_version = versions
    root = Root(version=root_version, expires=now + timedelta(days=90), consistent_snapshot=True)
    for role, signers in keys.items():
        for signer in signers:
            root.add_key(signer.public_key, role)
    root.roles["root"].threshold = 2
    old_keys = previous["root"] if previous else []
    (metadata / f"{root_version}.root.json").write_bytes(sign(root, [*old_keys, *keys["root"]]))
    target_index = sign(Targets(version=release_version, targets=targets, expires=now + timedelta(days=30)),
                        keys["targets"])
    (metadata / f"{release_version}.targets.json").write_bytes(target_index)
    snapshot = sign(Snapshot(version=release_version, expires=now + timedelta(days=3),
                             meta={"targets.json": MetaFile.from_data(release_version, target_index, ["sha256"])}),
                    keys["snapshot"])
    (metadata / f"{release_version}.snapshot.json").write_bytes(snapshot)
    expiry = now + timedelta(hours=-1 if expired else 12)
    timestamp = Timestamp(version=release_version, expires=expiry,
                          snapshot_meta=MetaFile.from_data(release_version, snapshot, ["sha256"]))
    (metadata / "timestamp.json").write_bytes(sign(timestamp, keys["timestamp"]))


def target_prefix(selection):
    return f"{selection['role']}-{selection['epoch']}-{selection['manifest_sha256']}"


def make_release(path, payloads, epoch, role, wrong_role=False):
    composition = {"role": "hypervisor" if wrong_role else role}
    members = {name: {"bytes": source.stat().st_size, "sha256": sha256(source)} for name, source in payloads.items()}
    composition.update((name, members[name.replace("_", "-") + ".raw"])
                       for name in (("boot", "vm_runtime", "guest_boot") if composition["role"] == "hypervisor"
                                    else ("guest_boot",)))
    data = encode_json({"schema": "fvca-os-release-v1", "epoch": epoch, "composition": composition,
                        "qualification": members["qualification.json"]})
    manifest_digest = hashlib.sha256(data).hexdigest()
    budget = sum(member["bytes"] for member in members.values()) + len(data)
    selection = {"role": role, "epoch": epoch, "minimum_epoch": epoch,
                 "manifest_sha256": manifest_digest, "max_release_bytes": budget}
    stem = target_prefix(selection)
    manifest = path / f"{stem}-release.json"
    manifest.write_bytes(data)
    return selection, {f"{stem}-{name}": source for name, source in {**payloads, "release.json": manifest}.items()}


def fixture(client, output, hypervisor, vm_runtime, guest):
    output.mkdir(mode=0o700)
    qualification = output / "qualification.json"
    write_json(qualification, {"profile": "disposable qualification fixture"})
    host = {"boot.raw": hypervisor, "vm-runtime.raw": vm_runtime, "guest-boot.raw": guest,
            "qualification.json": qualification}
    guest = {"guest-boot.raw": guest, "qualification.json": qualification}
    hypervisor, first = make_release(output, host, 17, "hypervisor")
    guest, second = make_release(output, guest, 19, "service-guest")
    wrong_role, third = make_release(output, host, 20, "service-guest", wrong_role=True)
    sources = first | second | third
    targets = {name: TargetFile.from_file(name, str(path), ["sha256"]) for name, path in sources.items()}
    now = datetime.now(UTC).replace(microsecond=0)
    old, new = new_keys(), new_keys()
    original = output / "depot-1"
    original.mkdir()
    files = original / "targets"
    files.mkdir()
    for name, source in sources.items():
        os.link(source, files / f"{targets[name].hashes['sha256']}.{name}")
    publish(original, (1, 1), old, now, targets)
    pinned = original / "metadata/1.root.json"

    def new_depot(name, *, keys=old, versions=(1, 2), previous=None, expired=False, index=targets):
        depot = output / name
        depot.mkdir()
        shutil.copytree(files, depot / "targets", copy_function=os.link)
        publish(depot, versions, keys, now, index, previous=previous, expired=expired)
        return depot

    def apply(name, depot, selection, persistent=None, failure=None):
        state = output / f"state-{persistent or name}"
        state.mkdir(mode=0o700, exist_ok=True)
        request = output / f"selection-{name}.json"
        write_json(request, selection)
        config = output / f"depot-{name}.json"
        write_json(config, {"transport": "local", "path": str(depot)})
        command = [client, pinned, config, state, request]
        result = subprocess.run(command, text=True, capture_output=True, check=False, timeout=120)
        (output / f"{name}.log").write_text(result.stdout + result.stderr)
        if failure:
            require(result.returncode != 0 and failure.lower() in result.stderr.lower(),
                    f"{name} did not reject for {failure!r}: {result}")
        else:
            require(result.returncode == 0 and result.stdout.startswith("FVCA_RELEASE_STAGED "),
                    f"{name} failed: {result}")
            staged = state / "staged" / selection["manifest_sha256"]
            stem = target_prefix(selection)
            expected = {target.removeprefix(stem + "-"): reference.hashes["sha256"]
                        for target, reference in targets.items() if target.startswith(stem + "-")}
            require({entry.name: sha256(entry) for entry in staged.iterdir()} == expected, f"{name} staged incorrect bytes")
        require(not list((state / "staged").glob(".stage-*")), f"{name} left an exposed partial release")
        print(f"{name} passed", flush=True)
        return state

    apply("stage-hypervisor", original, hypervisor)
    apply("stage-guest", original, guest)
    same_root = new_depot("same-root")
    apply("retry-hypervisor", same_root, hypervisor, persistent="stage-hypervisor")
    apply("metadata-rollback", original, hypervisor, persistent="stage-hypervisor", failure="previously fetched version")
    apply("wrong-role", original, wrong_role, failure="changes the authorized role")
    apply("wrong-epoch", original, hypervisor | {"minimum_epoch": 18}, failure="below the authorized minimum")
    wrong_manifest = hypervisor | {"manifest_sha256": "0" * 64}
    apply("wrong-manifest", original, wrong_manifest, failure="approved TUF target is missing")
    alias = f"{target_prefix(wrong_manifest)}-release.json"
    real_manifest = sources[f"{target_prefix(hypervisor)}-release.json"]
    reference = TargetFile.from_file(alias, str(real_manifest), ["sha256"])
    misaddressed = new_depot("misaddressed", index=targets | {alias: reference})
    os.link(real_manifest, misaddressed / "targets" / f"{reference.hashes['sha256']}.{alias}")
    apply("misaddressed-manifest", misaddressed, wrong_manifest, failure="digest or length")
    apply("short-budget", original, hypervisor | {"max_release_bytes": hypervisor["max_release_bytes"] - 1},
          failure="staging budget")
    expired = new_depot("expired", expired=True)
    apply("expired-timestamp", expired, hypervisor, failure="expired")

    broken = new_depot("broken")
    target = f"{target_prefix(hypervisor)}-vm-runtime.raw"
    damaged = broken / "targets" / f"{targets[target].hashes['sha256']}.{target}"
    damaged.unlink()
    shutil.copyfile(sources[target], damaged)
    with damaged.open("r+b") as stream:
        first_byte = stream.read(1)
        stream.seek(0)
        stream.write(bytes([first_byte[0] ^ 0xFF]))
    state = apply("corrupt-member", broken, hypervisor, failure="hash mismatch")
    require(not list((state / "staged").iterdir()), "failed download published a release")

    rotated = new_depot("rotated", keys=new, versions=(2, 2), previous=old)
    incomplete = new_depot("incomplete-rotation", keys=new, versions=(2, 2), previous=old)
    (incomplete / "metadata/timestamp.json").unlink()
    apply("incomplete-rotation", incomplete, guest, failure="timestamp.json")
    apply("rotated-root-rollback", original, guest, persistent="incomplete-rotation", failure="signature")
    apply("complete-rotation", rotated, guest, persistent="incomplete-rotation")

    symlink = new_depot("untrusted-symlink")
    (symlink / "metadata/2.root.json").symlink_to(rotated / "metadata/2.root.json")
    apply("symlink-root", symlink, guest, failure="symbolic link")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("client", "output", "hypervisor", "vm-runtime", "guest"):
        parser.add_argument(f"--{name}", type=lambda path: Path(path).absolute(), required=True)
    args = parser.parse_args()
    os.umask(0o077)
    fixture(args.client, args.output, args.hypervisor, args.vm_runtime, args.guest)


if __name__ == "__main__":
    main()
