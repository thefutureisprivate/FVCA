#!/usr/bin/env python3
"""Sign an independently reviewed Hypervisor trial receipt off the appliance."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from uuid import UUID

from hypervisor_trial import TRIAL_FIELDS, candidate_layout, fields, standing_fields


def sha256(value):
    if re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError("expected a lowercase SHA-256 digest")
    return value


def record(path, version, names):
    with path.open("rb") as stream:
        raw = stream.read(1025)
    return raw, fields(raw, version, names)


def prepare(args):
    trial_raw, trial = record(args.trial, "FVCA-HYPERVISOR-TRIAL-2", TRIAL_FIELDS)
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

    esp, devices, _ = candidate_layout(args.candidate, args.sector_size, trial)
    header = ("FVCA-HYPERVISOR-PROMOTION-1\n"
              f"candidate_esp_after_trial={esp}\n"
              f"stable_core={sha256(args.stable_core)}\nstable_runtime={sha256(args.stable_runtime)}\n"
              + "".join(f"{key}={value}\n" for key, value in devices.items()))
    return header.encode("ascii") + trial_raw + health_raw


def prepare_standing(args):
    with args.trial.open("rb") as stream:
        envelope = stream.read(2049)
    body = envelope[64:]
    if len(envelope) > 2048 or not body:
        raise ValueError("expected a bounded signed standing trial")
    with tempfile.TemporaryDirectory(prefix="fvca-trial-verify-") as work:
        message, signature = (Path(work) / name for name in ("trial", "signature"))
        message.write_bytes(body)
        signature.write_bytes(envelope[:64])
        result = subprocess.run(["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", args.trial_key,
                                 "-in", message, "-sigfile", signature], stdout=subprocess.DEVNULL)
        if result.returncode != 0:
            raise ValueError("the trial signature did not verify under the supplied public key")
    selected, trial = standing_fields(body)
    with args.standing_active.open("rb") as stream:
        record = stream.read(65537)
    with args.candidate_manifest.open("rb") as stream:
        manifest = stream.read(65537)
    if len(record) > 65536 or len(manifest) > 65536:
        raise ValueError("standing promotion release identity exceeds its size bound")
    active = json.loads(record)
    candidate = json.loads(manifest)
    if (active["role"] != "hypervisor" or active["slot"] not in ("a", "b")
            or str(active["epoch"]) != selected["stable_epoch"]
            or type(active["sequence"]) is not int or not 0 < active["sequence"] < args.candidate_sequence
            or args.candidate_sequence >= 2**64
            or candidate["schema"] != "fvca-os-release-v1"
            or str(candidate["epoch"]) != selected["candidate_epoch"]
            or candidate["composition"]["role"] != "hypervisor"):
        raise ValueError("standing promotion inputs do not name the advancing Hypervisor release")
    with args.candidate.open("rb") as stream:
        boot = {"bytes": args.candidate.stat().st_size, "sha256": hashlib.file_digest(stream, "sha256").hexdigest()}
    if candidate["composition"]["boot"] != boot:
        raise ValueError("candidate disk differs from the authorized release manifest")
    esp, devices, offset = candidate_layout(args.candidate, args.sector_size, trial)
    candidate_digest = hashlib.sha256(manifest).hexdigest()
    stable_digest = sha256(active["manifest_sha256"])
    if esp != sha256(trial["candidate_esp_sha256"]) or candidate_digest == stable_digest:
        raise ValueError("standing promotion requires the exact advancing signed trial image")
    with tempfile.TemporaryDirectory(prefix="fvca-promotion-loader-") as work:
        loader = Path(work) / "candidate.efi"
        subprocess.run(["mcopy", "-i", f"{args.candidate}@@{offset}", "::/EFI/BOOT/BOOTX64.EFI", loader],
                       check=True)
        size = loader.stat().st_size
        if not 0 < size <= 256 * 1024 * 1024:
            raise ValueError("standing promotion candidate UKI exceeds its size bound")
        with loader.open("rb") as stream:
            uki = hashlib.file_digest(stream, "sha256").hexdigest()
    if (sha256(selected["candidate_uki_sha256"]) != uki or selected["candidate_uki_bytes"] != str(size)
            or any(selected[key] != value for key, value in devices.items())):
        raise ValueError("candidate loader or verity partitions differ from the signed trial")
    header = (
        "FVCA-HYPERVISOR-STANDING-PROMOTION-2\n"
        f"stable_slot={active['slot']}\nstable_sequence={active['sequence']}\n"
        f"candidate_sequence={args.candidate_sequence}\n"
        f"stable_manifest_sha256={stable_digest}\ncandidate_manifest_sha256={candidate_digest}\n"
    )
    return header.encode("ascii") + body


def sign(args, message):
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
    for name in ("trial", "candidate", "sign-key", "output"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    for name in ("health", "standing-active", "candidate-manifest", "trial-key"):
        parser.add_argument(f"--{name}", type=Path)
    parser.add_argument("--stable-core")
    parser.add_argument("--stable-runtime")
    parser.add_argument("--candidate-sequence", type=int)
    parser.add_argument("--sector-size", type=int, choices=(512, 4096), default=4096)
    args = parser.parse_args()
    standing = (args.standing_active, args.candidate_manifest, args.trial_key, args.candidate_sequence)
    reviewed = (args.health, args.stable_core, args.stable_runtime)
    if any(value is not None for value in standing):
        if not all(value is not None for value in standing) or any(reviewed):
            parser.error("standing promotion requires the active record, new manifest and sequence, and trial public key")
        prepare_approval = prepare_standing
    else:
        if not all(reviewed):
            parser.error("reviewed promotion requires the health receipt and stable core and runtime hashes")
        prepare_approval = prepare
    try:
        sign(args, prepare_approval(args))
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"FVCA promotion approval failed: {error}\n")


if __name__ == "__main__":
    main()
