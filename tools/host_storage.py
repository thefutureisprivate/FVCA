"""Select and verify an encrypted Host data member before composing a disk."""

import base64
from dataclasses import dataclass
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from uuid import UUID

from image_verity import extract_partition, read_layout
from runtime_boot import run


AUTHENTICATED = "luks2-xts-hmac-sha256"
SUPPORT = "usr/lib/fvca/host-storage-support-v5"
BOOT_BINDING_SUPPORT = "usr/lib/fvca/host-storage-boot-binding-v1"
BOOT_ARGUMENT = "fvca.host_storage"
PCR_POLICY_REFS = {"tpm2-auto": "fvca-host-storage-auto-v1", "tpm2-pin": "fvca-host-storage"}
DATA_TYPE = "ca7d7ccb-63ed-4c53-861c-1742536059cc"
DATA_PARTITION = {"host_data": DATA_TYPE}


@dataclass(frozen=True)
class Member:
    partition: str
    volume: str
    token_index: str | None
    token_digest: str | None
    header_digest: str | None


@dataclass(frozen=True)
class Selection:
    raw: bytes
    unlock: str
    protection: str
    members: tuple[Member, Member]
    filesystem: str

    def boot_argument(self):
        digest = hashlib.sha256(self.raw).hexdigest()
        return f"{BOOT_ARGUMENT}={digest}," + ",".join(member.partition for member in self.members)


def selection(path):
    content = path.read_bytes()
    uuid = r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"
    token = r"(0|[1-9]|[12][0-9]|3[01]),([0-9a-f]{64}),([0-9a-f]{64})"
    match = re.fullmatch(
        rf"FVCA-HOST-STORAGE-5\nunlock=(development-passphrase|tpm2-auto|tpm2-pin)\n"
        rf"protection=(development-luks2|{AUTHENTICATED})\n"
        rf"member_a=({uuid}),({uuid})\nmember_b=({uuid}),({uuid})\n"
        rf"filesystem=btrfs\nfilesystem_uuid=({uuid})\n"
        rf"(?:token_a={token}\ntoken_b={token}\n)?",
        content.decode("ascii"),
    )
    if match is None:
        raise ValueError("invalid Hypervisor storage selection")
    (unlock, protection, partition_a, volume_a, partition_b, volume_b, filesystem,
     index_a, digest_a, header_a, index_b, digest_b, header_b) = match.groups()
    if partition_a == partition_b or volume_a == volume_b:
        raise ValueError("storage selection must name distinct partitions and LUKS2 volumes")
    uses_tpm = unlock != "development-passphrase"
    if (uses_tpm != (digest_a is not None)
            or (uses_tpm and (protection != AUTHENTICATED or digest_a == digest_b or header_a == header_b))):
        raise ValueError("TPM storage requires authenticated members with separate token and header authorization")
    members = (Member(partition_a, volume_a, index_a, digest_a, header_a),
               Member(partition_b, volume_b, index_b, digest_b, header_b))
    return Selection(content, unlock, protection, members, filesystem)


def unique_fields(pairs):
    fields = dict(pairs)
    if len(fields) != len(pairs):
        raise ValueError("duplicate fields in LUKS2 metadata")
    return fields


def authenticated_header(metadata):
    segments = metadata["segments"]
    segment = segments["0"].copy()
    offset = segment.pop("offset")
    expected = {"type": "crypt", "size": "dynamic", "iv_tweak": "0", "encryption": "aes-xts-plain64",
                "sector_size": 4096, "integrity": {"type": "hmac(sha256)", "journal_encryption": "none",
                                                    "journal_integrity": "none"}}
    config = metadata["config"]
    if (segments.keys() != {"0"} or segment != expected or re.fullmatch(r"[1-9][0-9]{0,19}", offset) is None
            or int(offset) % 4096 or int(offset) < 16384
            or config.get("flags") or config.get("requirements")):
        raise ValueError("Host data member lacks the approved journaled 4 KiB LUKS2 encryption profile")
    digests = [entry for entry in metadata["digests"].values() if entry["segments"] == ["0"]]
    if (len(digests) != 1 or not digests[0]["keyslots"]
            or any(metadata["keyslots"][index]["key_size"] != 96 for index in digests[0]["keyslots"])):
        raise ValueError("Host data member requires the 512-bit XTS key and 256-bit HMAC key")
    return int(offset)


@dataclass(frozen=True)
class Header:
    path: Path
    metadata: dict
    size: int
    payload_offset: int
    digest: str


def inspect_header(path, member):
    if not path.is_file() or not 0 < path.stat().st_size <= 128 * 1024**2:
        raise ValueError("expected a bounded LUKS2 header backup")
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if member.header_digest is not None and digest != member.header_digest:
        raise ValueError("LUKS2 header differs from the signed Host storage selection")
    if run("cryptsetup", "luksUUID", path, capture_output=True).stdout != (member.volume + "\n").encode("ascii"):
        raise ValueError("LUKS2 header has a different UUID from the selected member")
    raw = run("cryptsetup", "luksDump", "--dump-json-metadata", path, capture_output=True).stdout
    metadata = json.loads(raw, object_pairs_hook=unique_fields)
    payload_offset = authenticated_header(metadata)
    config = metadata["config"]
    extent = 2 * (4096 + int(config["json_size"])) + int(config["keyslots_size"])
    size = path.stat().st_size
    if size != extent or size > payload_offset or size % 4096:
        raise ValueError("expected exactly the aligned LUKS2 metadata and keyslot extent")
    return Header(path, metadata, size, payload_offset, digest)


def copy_header(source, destination, member):
    if not source.is_file() or not 0 < source.stat().st_size <= 128 * 1024**2:
        raise ValueError("expected a bounded LUKS2 header backup")
    shutil.copyfile(source, destination)
    return inspect_header(destination, member)


def independent_recovery_slot(metadata, slot):
    recovery_label = {"type": "systemd-recovery", "keyslots": [slot]}
    return slot in metadata["keyslots"] and all(
        slot not in token["keyslots"] or token == recovery_label for token in metadata["tokens"].values()
    )


def tpm_enrollment(header, member, unlock):
    """Return the PCR public key and independent recovery slot of a reviewed header."""
    metadata = header.metadata
    tokens = metadata["tokens"]
    token = tokens.get(member.token_index)
    if token is None or len(token["keyslots"]) != 1:
        raise ValueError("the selected TPM token must own exactly one keyslot")
    ordinary, = token["keyslots"]
    keyslots = metadata["keyslots"]
    recovery = set(keyslots) - {ordinary}
    if ordinary not in keyslots or len(recovery) != 1:
        raise ValueError("TPM enrollment requires exactly one ordinary and one independent recovery keyslot")
    slot, = recovery
    digests = list(metadata["digests"].values())
    if len(digests) != 1 or set(digests[0]["keyslots"]) != set(keyslots):
        raise ValueError("both authorized keyslots must cover the single authenticated LUKS2 payload")
    other_tokens = [item for index, item in tokens.items() if index != member.token_index]
    if other_tokens not in ([], [{"type": "systemd-recovery", "keyslots": [slot]}]):
        raise ValueError("unexpected token in the authorized Host TPM enrollment")
    raw = run("cryptsetup", "token", "export", "--token-id", member.token_index, header.path,
              capture_output=True).stdout
    if hashlib.sha256(raw).hexdigest() != member.token_digest:
        raise ValueError("LUKS2 TPM token differs from the signed Host storage selection")
    pin = unlock == "tpm2-pin"
    if (token["type"] != "systemd-tpm2" or token.get("tpm2-pin", False) is not pin
            or token["tpm2-pcrs"] != [7, 12, 13] or token["tpm2-pcr-bank"] != "sha256"
            or token["tpm2_pubkey_pcrs"] != [11] or token["tpm2_pubkey_ref"] != PCR_POLICY_REFS[unlock]):
        raise ValueError("LUKS2 token does not match the selected TPM unlock profile and PCR policy")
    for parameter in ("memcost", "iterations", "lanes"):
        field = f"tpm2_argon2id_{parameter}"
        if not pin and field in token:
            raise ValueError("the PIN-less LUKS2 token must omit PIN hardening parameters")
        value = token.get(field)
        if pin and (type(value) is not int or value < 1):
            raise ValueError("the LUKS2 token must harden the PIN with Argon2id")
    token_public = base64.b64decode(token["tpm2_pubkey"], validate=True)
    public = run("openssl", "pkey", "-pubin", "-outform", "DER", input=token_public, capture_output=True).stdout
    return public, slot


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
    if authenticated_header(metadata) >= size:
        raise ValueError("Host data partition has no space for the authorized LUKS2 payload")
    if selected.token_index is not None:
        with tempfile.TemporaryDirectory(prefix="luks2-header-", dir=destination.parent) as scratch:
            backup = Path(scratch) / "header"
            run("cryptsetup", "luksHeaderBackup", destination, "--header-backup-file", backup)
            inspect_header(backup, selected)
    return identifier
