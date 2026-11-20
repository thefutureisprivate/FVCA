"""Select and verify an encrypted Host data member before composing a disk."""

from dataclasses import dataclass
import hashlib
import json
import re
import subprocess
from uuid import UUID

from image_verity import extract_partition, read_layout
from runtime_boot import run


AUTHENTICATED = "luks2-xts-hmac-sha256"
DATA_TYPE = "ca7d7ccb-63ed-4c53-861c-1742536059cc"
DATA_PARTITION = {"host_data": DATA_TYPE}


@dataclass(frozen=True)
class Member:
    partition: str
    volume: str
    token_index: str | None
    token_digest: str | None


@dataclass(frozen=True)
class Selection:
    raw: bytes
    unlock: str
    protection: str
    members: tuple[Member, Member]


def selection(path):
    content = path.read_bytes()
    uuid = r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"
    token = r"(0|[1-9]|[12][0-9]|3[01]),([0-9a-f]{64})"
    match = re.fullmatch(
        rf"FVCA-HOST-STORAGE-4\nunlock=(development-passphrase|tpm2-auto|tpm2-pin)\n"
        rf"protection=(development-luks2|{AUTHENTICATED})\n"
        rf"member_a=({uuid}),({uuid})\nmember_b=({uuid}),({uuid})\n"
        rf"filesystem=btrfs\nfilesystem_uuid={uuid}\n"
        rf"(?:token_a={token}\ntoken_b={token}\n)?",
        content.decode("ascii"),
    )
    if match is None:
        raise ValueError("invalid Hypervisor storage selection")
    unlock, protection, partition_a, volume_a, partition_b, volume_b, index_a, digest_a, index_b, digest_b = match.groups()
    if partition_a == partition_b or volume_a == volume_b:
        raise ValueError("storage selection must name distinct partitions and LUKS2 volumes")
    uses_tpm = unlock != "development-passphrase"
    if uses_tpm != (digest_a is not None) or (uses_tpm and digest_a == digest_b):
        raise ValueError("TPM storage selection requires separate authorization for both tokens")
    members = (Member(partition_a, volume_a, index_a, digest_a), Member(partition_b, volume_b, index_b, digest_b))
    return Selection(content, unlock, protection, members)


def unique_fields(pairs):
    fields = dict(pairs)
    if len(fields) != len(pairs):
        raise ValueError("duplicate fields in LUKS2 metadata")
    return fields


def prepare_member(storage, disk, sector_size, destination):
    if storage.protection != AUTHENTICATED:
        raise ValueError("an integrated Host data member requires the authenticated storage profile")
    if not disk.is_file():
        raise ValueError("the Host data source must be a regular GPT image")
    run("sfdisk", "--verify", "--sector-size", str(sector_size), disk, stdout=subprocess.DEVNULL)
    sector, partitions = read_layout(disk, DATA_PARTITION, sector_size=sector_size)
    partition = partitions["host_data"]
    identifier = str(UUID(partition["uuid"]))
    selected = next((member for member in storage.members if member.partition == identifier), None)
    if selected is None:
        raise ValueError("Host data partition UUID is outside the signed storage selection")
    size = partition["size"] * sector
    if size <= 0 or size % 4096:
        raise ValueError("Host data partition size must be 4 KiB aligned")
    extract_partition(disk, partition, sector, destination)
    volume = run("cryptsetup", "luksUUID", destination, capture_output=True).stdout
    if volume != (selected.volume + "\n").encode("ascii"):
        raise ValueError("Host data LUKS2 UUID differs from the signed storage selection")
    raw = run("cryptsetup", "luksDump", "--dump-json-metadata", destination, capture_output=True).stdout
    metadata = json.loads(raw, object_pairs_hook=unique_fields)
    segments = metadata["segments"]
    segment = segments["0"]
    offset = segment.pop("offset")
    expected = {"type": "crypt", "size": "dynamic", "iv_tweak": "0", "encryption": "aes-xts-plain64",
                "sector_size": 4096, "integrity": {"type": "hmac(sha256)", "journal_encryption": "none",
                                                    "journal_integrity": "none"}}
    config = metadata["config"]
    if (segments.keys() != {"0"} or segment != expected or re.fullmatch(r"[1-9][0-9]{0,19}", offset) is None
            or int(offset) % 4096 or not 16384 <= int(offset) < size
            or config.get("flags") or config.get("requirements")):
        raise ValueError("Host data member lacks the approved journaled 4 KiB LUKS2 encryption profile")
    digests = [entry for entry in metadata["digests"].values() if entry["segments"] == ["0"]]
    if (len(digests) != 1 or not digests[0]["keyslots"]
            or any(metadata["keyslots"][index]["key_size"] != 96 for index in digests[0]["keyslots"])):
        raise ValueError("Host data member requires the 512-bit XTS key and 256-bit HMAC key")
    if selected.token_index is not None:
        raw = run("cryptsetup", "token", "export", "--token-id", selected.token_index, destination,
                  capture_output=True).stdout
        if hashlib.sha256(raw).hexdigest() != selected.token_digest:
            raise ValueError("Host data TPM token differs from the selected member authorization")
    return identifier
