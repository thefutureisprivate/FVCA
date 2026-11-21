#!/usr/bin/env python3
"""Authorize a reviewed staging core with an independent boot key."""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from guest_boot_bundle import public_key, sha256
from image_verity import read_layout
from runtime_boot import BOOT_EFI, PARTITIONS, TOOLS, run


def approved_sha256(value):
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise argparse.ArgumentTypeError("expected a lowercase SHA-256 digest")
    return value


def authorize(args, work):
    if public_key(args.staging_certificate) == public_key(args.boot_certificate):
        raise ValueError("the staging and boot authorities must use distinct keys")
    candidate = work / "authorized"
    candidate.mkdir(mode=0o700)
    disk = candidate / "core.raw"
    manifest = candidate / "core.manifest"
    initrd = candidate / "initrd.cpio.zst"
    run("cp", "--reflink=auto", "--sparse=always", "--", args.image, disk)
    shutil.copyfile(args.image.with_suffix(".manifest"), manifest)
    if sha256(disk) != args.image_sha256 or sha256(manifest) != args.manifest_sha256:
        raise ValueError("core image and package inventory must match their reviewed digests")

    run("python3", TOOLS / "verify-base.py", disk, args.staging_certificate, "--extract-initrd", initrd)
    sector_size, parts = read_layout(disk, PARTITIONS)
    staged_uki = work / "staged.efi"
    offset = parts["esp"]["start"] * sector_size
    run("mcopy", "-i", f"{disk}@@{offset}", BOOT_EFI, staged_uki)
    sections = json.loads(run("ukify", "--json=short", "inspect", staged_uki, capture_output=True).stdout)
    root_hash, = re.findall(r"(?:^|\s)roothash=([0-9a-f]{64})(?=\s|$)", sections[".cmdline"]["text"])

    run("sbattach", "--remove", staged_uki)
    boot = work / "boot.efi"
    run("sbsign", "--key", args.boot_key, "--cert", args.boot_certificate, "--output", boot, staged_uki)
    signatures = run("sbverify", "--list", boot, capture_output=True, text=True).stdout
    if re.findall(r"^signature [0-9]+$", signatures, re.MULTILINE) != ["signature 1"]:
        raise ValueError("the authorized UKI must carry exactly one signature")
    if subprocess.run(["sbverify", "--cert", args.staging_certificate, boot],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 1:
        raise ValueError("the authorized UKI must reject the staging authority")

    # A fresh ESP carries the authorized boot image without staging enrollment data.
    esp = work / "esp"
    esp_bytes = parts["esp"]["size"] * sector_size
    with esp.open("xb") as target:
        target.truncate(esp_bytes)
    run("mkfs.fat", "-F", "32", "-S", str(sector_size), "-s", "1", esp)
    run("mmd", "-i", esp, "::/EFI", "::/EFI/BOOT")
    run("mcopy", "-i", esp, boot, BOOT_EFI)

    content = work / "roothash"
    content.write_text(root_hash, encoding="ascii")
    signature = work / "root.p7s"
    run("openssl", "cms", "-sign", "-binary", "-nocerts", "-noattr", "-outform", "DER",
        "-in", content, "-signer", args.boot_certificate, "-inkey", args.boot_key, "-out", signature)
    certificate = run("openssl", "x509", "-in", args.boot_certificate, "-outform", "DER", capture_output=True).stdout
    record = json.dumps({
        "rootHash": root_hash,
        "certificateFingerprint": hashlib.sha256(certificate).hexdigest(),
        "signature": base64.b64encode(signature.read_bytes()).decode("ascii"),
    }).encode("ascii")
    signature_bytes = parts["signature"]["size"] * sector_size
    if len(record) > signature_bytes or esp.stat().st_size != esp_bytes:
        raise ValueError("the replacement boot material must fit the original GPT partitions")
    with disk.open("r+b") as output, esp.open("rb") as boot_fs:
        output.seek(offset)
        shutil.copyfileobj(boot_fs, output, length=1024 * 1024)
        output.seek(parts["signature"]["start"] * sector_size)
        output.write(record.ljust(signature_bytes, b"\0"))

    run("python3", TOOLS / "verify-base.py", disk, args.boot_certificate)
    run("mv", "--no-target-directory", "--update=none-fail", "--", candidate, args.output)
    print(f"Authorized the reviewed core under the independent boot authority at {root_hash}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    for name in ("staging-certificate", "boot-certificate", "boot-key", "output"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--image-sha256", required=True, type=approved_sha256)
    parser.add_argument("--manifest-sha256", required=True, type=approved_sha256)
    args = parser.parse_args()
    try:
        if args.output.exists() or args.output.is_symlink():
            raise ValueError("use a new output directory")
        with tempfile.TemporaryDirectory(prefix=".fvca-core-", dir=args.output.parent) as work:
            authorize(args, Path(work))
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"FVCA core authorization failed: {error}\n")


if __name__ == "__main__":
    main()
