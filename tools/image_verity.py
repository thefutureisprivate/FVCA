"""Verify the fixed GPT and signed dm-verity data shared by FVCA images."""

import base64
import json
import re
import subprocess
from uuid import UUID


VERITY_PARTITIONS = {
    "root": "4f68bce3-e8cd-4db1-96e7-fbcaf984b709",
    "verity": "2c7357ed-ebd2-46d9-aec1-23d437ec2bf5",
    "signature": "41092b05-9fc8-4523-994f-2def0408b176",
}


def read_layout(image, partition_types, *, sector_size=None):
    options = ("--sector-size", str(sector_size)) if sector_size is not None else ()
    output = subprocess.check_output(["sfdisk", "--json", *options, image])
    table = json.loads(output)["partitiontable"]
    entries = table["partitions"]
    actual_types = sorted(partition["type"].lower() for partition in entries)
    if (table["label"] != "gpt" or actual_types != sorted(partition_types.values())
            or (sector_size is not None and table["sectorsize"] != sector_size)):
        raise ValueError(f"expected exactly these GPT partitions: {', '.join(partition_types)}")

    by_type = {entry["type"].lower(): entry for entry in entries}
    return table["sectorsize"], {name: by_type[guid] for name, guid in partition_types.items()}


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


def verify_cms(content, signature, certificate):
    # Trust the explicitly supplied signer and ignore certificates embedded by the candidate.
    subprocess.run(["openssl", "cms", "-verify", "-binary", "-inform", "DER", "-in", signature,
                    "-content", content, "-nointern", "-certfile", certificate, "-noverify",
                    "-out", "/dev/null"], check=True)


def verify_verity(image, sector_size, partitions, certificate, work, expected_hash=None):
    for name in VERITY_PARTITIONS:
        extract_partition(image, partitions[name], sector_size, work / name)

    signed_root = json.loads((work / "signature").read_bytes().rstrip(b"\0"))
    root_hash = signed_root["rootHash"]
    if re.fullmatch(r"[0-9a-f]{64}", root_hash) is None:
        raise ValueError("the signed partition must specify a SHA-256 root hash")
    if expected_hash is not None and root_hash != expected_hash:
        raise ValueError("DDI root hash differs from the expected root hash")

    root_uuid = UUID(partitions["root"]["uuid"]).hex
    verity_uuid = UUID(partitions["verity"]["uuid"]).hex
    if root_uuid + verity_uuid != root_hash:
        raise ValueError("GPT partition UUIDs do not match the signed root hash")

    signature = work / "root.p7s"
    signature.write_bytes(base64.b64decode(signed_root["signature"], validate=True))
    content = work / "roothash"
    content.write_text(root_hash, encoding="ascii")
    verify_cms(content, signature, certificate)
    subprocess.run(["veritysetup", "verify", work / "root", work / "verity", root_hash], check=True)
    return root_hash
