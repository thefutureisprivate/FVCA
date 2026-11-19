#!/usr/bin/env python3
"""Verify the boot and root artifacts in an FVCA development disk off-node."""

import argparse
import base64
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from uuid import UUID


PARTITIONS = {
    "esp": "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
    "root": "4f68bce3-e8cd-4db1-96e7-fbcaf984b709",
    "verity": "2c7357ed-ebd2-46d9-aec1-23d437ec2bf5",
    "signature": "41092b05-9fc8-4523-994f-2def0408b176",
}


def read_layout(image):
    output = subprocess.check_output(["sfdisk", "--json", image])
    table = json.loads(output)["partitiontable"]
    entries = table["partitions"]
    actual_types = sorted(partition["type"].lower() for partition in entries)
    if table["label"] != "gpt" or actual_types != sorted(PARTITIONS.values()):
        raise ValueError("expected one ESP, root, root-verity and root-verity-signature partition")

    by_type = {p["type"].lower(): p for p in entries}
    return table["sectorsize"], {name: by_type[guid] for name, guid in PARTITIONS.items()}


def extract_partition(image, partition, sector_size, destination):
    remaining = partition["size"] * sector_size
    with image.open("rb") as source, destination.open("wb") as result:
        source.seek(partition["start"] * sector_size)
        while remaining:
            data = source.read(min(remaining, 1024 * 1024))
            if not data:
                raise ValueError(f"incomplete {destination.name} partition")
            result.write(data)
            remaining -= len(data)


def verify(image, boot_certificate, verity_certificate, work):
    sector_size, partitions = read_layout(image)
    uki = work / "boot.efi"
    esp_offset = partitions["esp"]["start"] * sector_size
    subprocess.run(["mcopy", "-i", f"{image}@@{esp_offset}", "::/EFI/BOOT/BOOTX64.EFI", uki], check=True)
    subprocess.run(["sbverify", "--cert", boot_certificate, uki], check=True)
    sections = json.loads(subprocess.check_output(["ukify", "--json=short", "inspect", uki]))
    if sections.get("_profiles"):
        raise ValueError("unexpected UKI profiles")

    hashes = [
        arg.removeprefix("roothash=")
        for arg in sections[".cmdline"]["text"].split()
        if arg.startswith("roothash=")
    ]
    if len(hashes) != 1 or re.fullmatch(r"[0-9a-f]{64}", hashes[0]) is None:
        raise ValueError("the signed UKI must specify one SHA-256 root hash")
    root_hash = hashes[0]
    root_uuid = UUID(partitions["root"]["uuid"]).hex
    verity_uuid = UUID(partitions["verity"]["uuid"]).hex
    if root_uuid + verity_uuid != root_hash:
        raise ValueError("GPT partition UUIDs do not match the signed UKI root hash")

    for name in ("root", "verity", "signature"):
        extract_partition(image, partitions[name], sector_size, work / name)

    signed_root = json.loads((work / "signature").read_bytes().rstrip(b"\0"))
    if signed_root["rootHash"] != root_hash:
        raise ValueError("DDI signature partition root hash differs from the signed UKI")

    signature = work / "root.p7s"
    signature.write_bytes(base64.b64decode(signed_root["signature"], validate=True))
    content = work / "roothash"
    content.write_text(root_hash, encoding="ascii")
    # Trust the explicitly supplied signer and ignore certificates embedded by the candidate.
    subprocess.run(["openssl", "cms", "-verify", "-binary", "-inform", "DER", "-in", signature,
                    "-content", content, "-nointern", "-certfile", verity_certificate, "-noverify",
                    "-out", "/dev/null"], check=True)
    subprocess.run(["veritysetup", "verify", work / "root", work / "verity", root_hash], check=True)
    print(f"Verified UKI, DDI signature and dm-verity data for {root_hash}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=lambda value: Path(value).resolve())
    parser.add_argument("boot_certificate", type=Path)
    parser.add_argument("--verity-certificate", type=Path, help="defaults to the boot certificate")
    args = parser.parse_args()
    for tool in ("mcopy", "openssl", "sbverify", "sfdisk", "ukify", "veritysetup"):
        if shutil.which(tool) is None:
            parser.exit(1, f"Required tool is missing: {tool}\n")

    try:
        with tempfile.TemporaryDirectory(prefix="fvca-verify-") as directory:
            verify(args.image, args.boot_certificate, args.verity_certificate or args.boot_certificate, Path(directory))
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print(f"FVCA image verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
