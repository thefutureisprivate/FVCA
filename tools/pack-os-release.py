#!/usr/bin/env python3
"""Prepare unsigned TUF targets for an independently reviewed FVCA OS release."""

import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile

from image_verity import VERITY_PARTITIONS, read_layout, verify_verity
from runtime_boot import run
from workload_oci import file_record as hashed_file, json_bytes, open_regular, parse_json, read_bytes


MANIFEST_LIMIT = 64 * 1024
INVENTORY_LIMIT = 64 * 1024**2
U64_MAX = 2**64 - 1
GUEST_INVENTORY = "service-guest-boot-inventory.json"
HOST_INVENTORY = "hypervisor-boot-inventory.json"
VERITY_FIELDS = ("verity_root", "data_sha256", "verity_tree_sha256")
ARTIFACTS = {
    "service-guest": {"guest-boot.raw": "guest_boot"},
    "hypervisor": {"boot.raw": "boot", "vm-runtime.raw": "vm_runtime", "guest-boot.raw": "guest_boot"},
}


def valid_digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def file_record(path, limit=U64_MAX - 1):
    identity = hashed_file(path, limit)
    return {"bytes": identity["size"], "sha256": identity["digest"].removeprefix("sha256:")}


def data_record(data):
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def records(values):
    if not isinstance(values, dict):
        raise ValueError("expected an object containing reviewed file records")
    for name, member in values.items():
        if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", name)
                or not isinstance(member, dict) or member.keys() != {"bytes", "sha256"}
                or type(member["bytes"]) is not int or not 0 < member["bytes"] < U64_MAX
                or not valid_digest(member["sha256"])):
            raise ValueError(f"invalid reviewed file record for {name}")


def approved_review(args):
    data = read_bytes(args.review, MANIFEST_LIMIT)
    if data_record(data)["sha256"] != args.review_sha256:
        raise ValueError("qualification review differs from the independently approved digest")
    review = parse_json(data)
    if (not isinstance(review, dict) or review.keys() != {"schema", "role", "epoch", "artifacts", "evidence"}
            or review["schema"] != "fvca-os-release-review-v1" or review["role"] not in ARTIFACTS
            or type(review["epoch"]) is not int or not 0 < args.minimum_epoch <= review["epoch"] <= U64_MAX):
        raise ValueError("invalid qualification review role, schema or security epoch")
    records(review["artifacts"])
    records(review["evidence"])
    if review["artifacts"].keys() != ARTIFACTS[review["role"]].keys():
        raise ValueError("review must cover the complete exact role composition")
    needed = {GUEST_INVENTORY, "qualification.log"}
    if review["role"] == "hypervisor":
        needed.add(HOST_INVENTORY)
    if not needed <= review["evidence"].keys():
        raise ValueError("review must bind the boot inventories and qualification log")
    if (review["role"] == "hypervisor") != (args.vm_runtime_certificate is not None):
        raise ValueError("a VM runtime certificate is required for a Hypervisor release")
    return data, review


def reviewed_evidence(directory, members):
    inventories = {}
    for name, reference in members.items():
        path = directory / name
        is_inventory = name in (HOST_INVENTORY, GUEST_INVENTORY)
        limit = reference["bytes"]
        data = read_bytes(path, min(limit, INVENTORY_LIMIT)) if is_inventory else None
        if (data_record(data) if data is not None else file_record(path, limit)) != reference:
            raise ValueError(f"evidence differs from the qualification review: {name}")
        if data is not None:
            report = parse_json(data)
            role = name.removesuffix("-boot-inventory.json")
            if (not isinstance(report, dict) or report.get("schema") != "fvca-boot-inventory-v1"
                    or report.get("role") != role):
                raise ValueError(f"unexpected boot inventory for {role}")
            inventories[role] = report
    return inventories


def require_identity(actual, expected, message):
    if any(not valid_digest(actual[field]) or actual[field] != expected[field] for field in VERITY_FIELDS):
        raise ValueError(message)


def check_composition(args, review, inventories, payloads, work):
    guest = inventories["service-guest"]
    capsule = guest.get("capsule_image")
    if not isinstance(capsule, dict) or capsule.get("sha256") != review["artifacts"]["guest-boot.raw"]["sha256"]:
        raise ValueError("Guest inventory must cover the exact packed boot image")
    if review["role"] == "hypervisor":
        host = inventories["hypervisor"]
        if host.get("slot_sha256") != review["artifacts"]["boot.raw"]["sha256"]:
            raise ValueError("Hypervisor inventory does not cover the exact boot slot")
        require_identity(capsule, host["guest_capsule"], "detached Guest boot differs from the embedded Guest")
        if guest["guest_release"] != host["guest_release"]:
            raise ValueError("Hypervisor and Guest inventories cover different Guest releases")
        if capsule["signer_sha256"] != host["boot_signer_sha256"]:
            raise ValueError("the detached Guest capsule differs from the Host verity authority")

        runtime = payloads / "vm-runtime.raw"
        run("sfdisk", "--verify", "--sector-size", "512", runtime, stdout=subprocess.DEVNULL)
        sector, partitions = read_layout(runtime, VERITY_PARTITIONS, sector_size=512)
        root_hash = verify_verity(
            runtime, sector, partitions, args.vm_runtime_certificate, work, host["runtime"]["verity_root"],
        )
        require_identity({
            "verity_root": root_hash, "data_sha256": file_record(work / "root")["sha256"],
            "verity_tree_sha256": file_record(work / "verity")["sha256"],
        }, host["runtime"], "detached VM runtime differs from the embedded runtime")


def pack(args, work):
    approved_bytes, review = approved_review(args)
    role, epoch = review["role"], review["epoch"]
    inventories = reviewed_evidence(args.evidence_directory, review["evidence"])
    payloads = work / "payloads"
    payloads.mkdir()
    for name, record in review["artifacts"].items():
        with open_regular(args.artifact_directory / name) as source:
            if os.fstat(source.fileno()).st_size != record["bytes"]:
                raise ValueError(f"artifact length differs from the qualification review: {name}")
            # Copy from the checked file descriptor, then verify the snapshot used for publication.
            run("cp", "--reflink=auto", "--sparse=always", "--", f"/proc/self/fd/{source.fileno()}", payloads / name,
                pass_fds=(source.fileno(),))
        if file_record(payloads / name, record["bytes"]) != record:
            raise ValueError(f"artifact differs from the qualification review: {name}")

    check_composition(args, review, inventories, payloads, work)
    (payloads / "qualification.json").write_bytes(approved_bytes)
    members = review["artifacts"] | {"qualification.json": data_record(approved_bytes)}
    (payloads / "release.json").write_bytes(json_bytes({
        "schema": "fvca-os-release-v1", "epoch": epoch,
        "composition": {"role": role} | {field: members[name] for name, field in ARTIFACTS[role].items()},
        "qualification": members["qualification.json"],
    }))
    manifest = file_record(payloads / "release.json")
    members["release.json"] = manifest
    budget = sum(member["bytes"] for member in members.values())
    if budget >= U64_MAX:
        raise ValueError("release exceeds the intake staging limit")

    prepared = work / "release"
    targets = prepared / "targets"
    targets.mkdir(parents=True, mode=0o700)
    stem = f"{role}-{epoch}-{manifest['sha256']}"
    target_records = {}
    for name, member in members.items():
        logical = f"{stem}-{name}"
        digest = member["sha256"]
        (payloads / name).rename(targets / f"{digest}.{logical}")
        target_records[logical] = {"length": member["bytes"], "hashes": {"sha256": digest}}

    (prepared / "target-records.json").write_bytes(json_bytes(target_records))
    (prepared / "selection.json").write_bytes(json_bytes({
        "role": role, "epoch": epoch, "minimum_epoch": args.minimum_epoch,
        "manifest_sha256": manifest["sha256"], "max_release_bytes": budget,
    }))
    run("mv", "--no-clobber", "--no-target-directory", "--", prepared, args.output)
    if prepared.exists():
        raise FileExistsError(args.output)
    print(f"FVCA_RELEASE_TARGETS_PREPARED {stem}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("review", "artifact-directory", "evidence-directory", "output"):
        parser.add_argument(f"--{option}", type=Path, required=True)
    parser.add_argument("--review-sha256", required=True, help="independently approved SHA-256 of the review")
    parser.add_argument("--minimum-epoch", type=int, required=True)
    parser.add_argument("--vm-runtime-certificate", type=Path)
    args = parser.parse_args()
    try:
        if args.output.exists() or args.output.is_symlink():
            raise FileExistsError(args.output)
        with tempfile.TemporaryDirectory(prefix=".fvca-os-release-", dir=args.output.parent) as directory:
            pack(args, Path(directory))
    except (KeyError, OSError, TypeError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"FVCA OS release preparation failed: {error}\n")


if __name__ == "__main__":
    main()
