#!/usr/bin/env python3
"""Sign an independently reviewed Hypervisor trial receipt off the appliance."""

import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile
from uuid import UUID

import hypervisor_gpt
from image_verity import read_layout


def sha256(value):
    if re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError("expected a lowercase SHA-256 digest")
    return value


def record(path, version, names):
    with path.open("rb") as stream:
        raw = stream.read(1025)
    lines = raw.decode("ascii").split("\n")
    if len(raw) > 1024 or lines[0] != version or lines[-1] or len(lines) != len(names) + 2:
        raise ValueError(f"invalid {version} record")
    entries = {}
    for field, line in zip(names, lines[1:-1], strict=True):
        key, _, value = line.partition("=")
        if key != field or not value:
            raise ValueError(f"invalid {version} field {field}")
        entries[key] = value
    return raw, entries


def prepare(args):
    trial_raw, trial = record(args.trial, "FVCA-HYPERVISOR-TRIAL-2", (
        "transaction", "stable", "candidate", "candidate_esp_sha256", "candidate_esp_bytes",
        "candidate_core", "candidate_runtime", "guest_bundle",
    ))
    health_raw, health = record(args.health, "FVCA-HYPERVISOR-TRIAL-HEALTH-1", (
        "transaction", "boot_id", "candidate", "candidate_esp_sha256", "core_root", "guest_bundle", "vm_runtime",
    ))
    for field in ("transaction", "boot_id"):
        if str(UUID(health[field])) != health[field]:
            raise ValueError(f"invalid {field} UUID")
    expected = (trial["transaction"], trial["candidate"].partition(",")[2], sha256(trial["candidate_esp_sha256"]),
                sha256(trial["candidate_core"]), sha256(trial["guest_bundle"]), sha256(trial["candidate_runtime"]))
    if tuple(value for key, value in health.items() if key != "boot_id") != expected:
        raise ValueError("the health receipt differs from the authorized trial")

    sector, parts = read_layout(args.candidate, hypervisor_gpt.PARTITIONS, sector_size=args.sector_size)
    ids = {name: str(UUID(part["uuid"])) for name, part in parts.items()}
    size = parts["esp"]["size"] * sector
    if len(set(ids.values())) != len(parts) or ids["esp"] != health["candidate"] or str(size) != trial["candidate_esp_bytes"]:
        raise ValueError("candidate disk layout differs from the trial")
    digest = hashlib.sha256()
    with args.candidate.open("rb") as stream:
        stream.seek(parts["esp"]["start"] * sector)
        remaining = size
        while remaining:
            block = stream.read(min(remaining, 1024 * 1024))
            if not block:
                raise ValueError("candidate ESP is incomplete")
            digest.update(block)
            remaining -= len(block)

    header = ("FVCA-HYPERVISOR-PROMOTION-1\n"
              f"candidate_esp_after_trial={digest.hexdigest()}\n"
              f"stable_core={sha256(args.stable_core)}\nstable_runtime={sha256(args.stable_runtime)}\n"
              + "".join(f"candidate_{name}_devices={ids[name]},{ids[f'{name}_verity']}\n"
                        for name in ("core", "runtime", "guest")))
    message = header.encode("ascii") + trial_raw + health_raw
    if len(message) + 64 > 2048:
        raise ValueError("promotion approval is too large")
    public = subprocess.check_output(["openssl", "pkey", "-in", args.sign_key, "-pubout", "-outform", "DER"])
    if len(public) != 44 or not public.startswith(bytes.fromhex("302a300506032b6570032100")):
        raise ValueError("promotion must be signed with Ed25519")
    with tempfile.TemporaryDirectory(prefix="fvca-promotion-") as work:
        payload = Path(work) / "approval"
        payload.write_bytes(message)
        signature = subprocess.check_output(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", args.sign_key,
                                             "-in", payload])
    if len(signature) != 64:
        raise ValueError("promotion must be signed with Ed25519")
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(signature + message)
        stream.flush()
        os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("trial", "health", "candidate", "sign-key", "output"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--stable-core", required=True)
    parser.add_argument("--stable-runtime", required=True)
    parser.add_argument("--sector-size", type=int, choices=(512, 4096), default=4096)
    try:
        prepare(parser.parse_args())
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"FVCA promotion approval failed: {error}\n")


if __name__ == "__main__":
    main()
