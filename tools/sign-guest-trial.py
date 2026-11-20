#!/usr/bin/env python3
"""Approve an exact Service Guest boot image for a compatible-data trial."""

import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile
from uuid import UUID

import guest_boot_bundle
from runtime_boot import run


GUEST = "e629aa43-af11-47c6-aedc-a2dc47f1cc3a"
ED25519 = bytes.fromhex("302a300506032b6570032100")


def approve(args, work):
    if args.candidate.is_symlink() or not args.candidate.is_file():
        raise ValueError("Guest trial requires a regular candidate image")
    image = work / "guest-boot.raw"
    run("cp", "--reflink=auto", "--sparse=always", "--", args.candidate, image)
    size = image.stat().st_size
    if not 0 < size <= 4 * 1024**3 or size % 512:
        raise ValueError("Guest trial image exceeds its size bound")
    boot, selection = guest_boot_bundle.select_image(image, args.verity_certificate, args.release_certificate, work)
    if boot == args.stable_bundle:
        raise ValueError("the Guest trial must select a different candidate bundle")
    signer = subprocess.check_output(["openssl", "pkey", "-in", args.sign_key, "-pubout", "-outform", "DER"])
    if not signer.startswith(ED25519) or len(signer) != len(ED25519) + 32:
        raise ValueError("Guest trials require an Ed25519 signing key")
    for certificate in (args.verity_certificate, args.release_certificate):
        authority = guest_boot_bundle.public_key(certificate)
        if signer == run("openssl", "pkey", "-pubin", "-outform", "DER", input=authority, capture_output=True).stdout:
            raise ValueError("Guest trial approval requires a separate signing key")
    header = (
        "FVCA-GUEST-TRIAL-1\n"
        f"transaction={args.transaction}\nguest={GUEST}\nstable_bundle={args.stable_bundle}\n"
        f"stable_epoch={args.stable_epoch}\ncandidate_epoch={args.candidate_epoch}\n"
        f"not_before={args.not_before}\nexpires={args.expires}\nhealth_seconds={args.health_seconds}\n"
        f"data=compatible\ncandidate_image_sha256={guest_boot_bundle.sha256(image)}\ncandidate_image_bytes={size}\n"
    )
    body = work / "trial"
    body.write_bytes(header.encode("ascii") + selection)
    proof = subprocess.check_output([
        "openssl", "pkeyutl", "-sign", "-rawin", "-inkey", args.sign_key, "-in", body,
    ])
    if len(proof) != 64:
        raise ValueError("invalid Guest trial signature")
    with os.fdopen(os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
        output.write(proof + body.read_bytes())
        output.flush()
        os.fsync(output.fileno())
    parent = os.open(args.output.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    print(f"FVCA signed Guest trial {args.transaction} for bundle {boot}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("candidate", "release-certificate", "verity-certificate", "sign-key", "output"):
        parser.add_argument(f"--{name}", required=True, type=lambda value: Path(value).absolute())
    for name in ("stable-epoch", "candidate-epoch", "not-before", "expires", "health-seconds"):
        parser.add_argument(f"--{name}", type=int, required=True)
    parser.add_argument("--stable-bundle", required=True)
    parser.add_argument("--transaction", type=UUID, required=True)
    parser.add_argument("--compatible-data", action="store_true",
                        help="confirm both selected releases can use the same mutable Guest data")
    args = parser.parse_args()
    if not args.compatible_data:
        parser.error("the approval requires reviewed compatibility with the current mutable data")
    if (re.fullmatch(r"[0-9a-f]{64}", args.stable_bundle) is None
            or not 0 < args.stable_epoch <= args.candidate_epoch < 2**64
            or not 0 < args.not_before < args.expires < 2**64
            or args.expires - args.not_before > 86400 or not 10 <= args.health_seconds <= 300):
        parser.error("invalid trial epoch, launch deadline, validity interval or stable bundle")
    try:
        with tempfile.TemporaryDirectory(prefix=".fvca-sign-guest-", dir=args.output.parent) as directory:
            approve(args, Path(directory))
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"FVCA Guest trial approval failed: {error}\n")


if __name__ == "__main__":
    main()
