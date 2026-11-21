"""Read the fixed Hypervisor trial records and slot layout for off-node approval."""

import hashlib
from uuid import UUID

import hypervisor_gpt
from host_storage import DATA_PARTITION
from image_verity import read_layout


TRIAL_FIELDS = ("transaction", "stable", "candidate", "candidate_esp_sha256", "candidate_esp_bytes",
                "candidate_core", "candidate_runtime", "guest_bundle")
STANDING_FIELDS = ("not_before", "expires", "stable_epoch", "candidate_epoch", "epoch_policy_sha256",
                   "stable_core", "stable_runtime", "stable_guest_bundle", "candidate_uki_sha256",
                   "candidate_uki_bytes", "candidate_core_devices", "candidate_runtime_devices",
                   "candidate_guest_devices")


def fields(raw, version, names):
    lines = raw.decode("ascii").split("\n")
    if len(raw) > 1024 or lines[0] != version or lines[-1] or len(lines) != len(names) + 2:
        raise ValueError(f"invalid {version} record")
    entries = {}
    for field, line in zip(names, lines[1:-1], strict=True):
        key, _, value = line.partition("=")
        if key != field or not value:
            raise ValueError(f"invalid {version} field {field}")
        entries[key] = value
    return entries


def standing_fields(body):
    scope, separator, trial = body.partition(b"FVCA-HYPERVISOR-TRIAL-2\n")
    return (fields(scope, "FVCA-HYPERVISOR-STANDING-TRIAL-2", STANDING_FIELDS),
            fields(separator + trial, "FVCA-HYPERVISOR-TRIAL-2", TRIAL_FIELDS))


def slot_layout(image, sector_size):
    sector, parts = read_layout(image, hypervisor_gpt.PARTITIONS, sector_size=sector_size,
                                optional_types=DATA_PARTITION)
    ids = {name: str(UUID(part["uuid"])) for name, part in parts.items()}
    if any(UUID(value).int == 0 for value in ids.values()) or len(set(ids.values())) != len(parts):
        raise ValueError("Hypervisor slot partition identities must be distinct and nonzero")
    offset = parts["esp"]["start"] * sector
    size = parts["esp"]["size"] * sector
    return ids, offset, size


def candidate_layout(image, sector_size, trial):
    ids, offset, size = slot_layout(image, sector_size)
    if ids["esp"] != trial["candidate"].partition(",")[2] or str(size) != trial["candidate_esp_bytes"]:
        raise ValueError("candidate disk layout differs from the trial")
    digest = hashlib.sha256()
    with image.open("rb") as stream:
        stream.seek(offset)
        remaining = size
        while remaining:
            block = stream.read(min(remaining, 1024 * 1024))
            if not block:
                raise ValueError("candidate ESP is incomplete")
            digest.update(block)
            remaining -= len(block)
    devices = {f"candidate_{name}_devices": f"{ids[name]},{ids[f'{name}_verity']}"
               for name in ("core", "runtime", "guest")}
    return digest.hexdigest(), devices, offset
