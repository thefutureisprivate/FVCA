"""Validate and snapshot exact OCI inputs for workload derivation."""

import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import stat


INDEX = "application/vnd.oci.image.index.v1+json"
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
CONFIG = "application/vnd.oci.image.config.v1+json"
LAYER = "application/vnd.oci.image.layer.v1.tar"
LAYER_MEDIA = {LAYER, f"{LAYER}+gzip", f"{LAYER}+zstd"}
PLATFORM = {"os": "linux", "architecture": "amd64"}
METADATA_LIMIT = 4 * 1024**2
COMPRESSED_LIMIT = 256 * 1024**2
DECOMPRESSED_LIMIT = 640 * 1024**2
DIGEST = re.compile(r"sha256:([a-f0-9]{64})")


def digest_hex(value):
    match = DIGEST.fullmatch(value)
    if match is None:
        raise ValueError("expected a lowercase SHA-256 digest")
    return match[1]


def sha256(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def fields(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("duplicate JSON fields")
    return result


def invalid_constant(value):
    raise ValueError(f"invalid JSON constant {value}")


def parse_json(data):
    return json.loads(data.decode("utf-8"), object_pairs_hook=fields, parse_constant=invalid_constant)


def json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n"


def open_regular(path):
    stream = os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb")
    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
        stream.close()
        raise ValueError(f"expected a regular file at {path}")
    return stream


def read_bytes(path, limit=METADATA_LIMIT):
    with open_regular(path) as stream:
        result = stream.read(limit + 1)
    if len(result) > limit:
        raise ValueError(f"{path.name} exceeds the size limit")
    return result


def file_record(path, limit):
    with open_regular(path) as stream:
        before = os.fstat(stream.fileno())
        if not 0 < before.st_size <= limit:
            raise ValueError(f"{path.name} exceeds the size limit or is empty")
        total = 0
        digest = hashlib.sha256()
        while chunk := stream.read(1024 * 1024):
            total += len(chunk)
            if total > before.st_size:
                raise ValueError(f"{path.name} changed while being read")
            digest.update(chunk)
        if total != before.st_size:
            raise ValueError(f"{path.name} changed while being read")
    return {"digest": f"sha256:{digest.hexdigest()}", "size": total}


def absolute_path(value):
    if not isinstance(value, str) or not value.startswith("/") or "\0" in value:
        raise ValueError("expected an absolute container path")
    path = PurePosixPath(value)
    if str(path) != value or value.startswith("//") or ".." in path.parts:
        raise ValueError("expected a normalized container path")
    return value


def validate_policy(policy):
    if policy.keys() != {
        "schema", "service", "repository", "index", "manifest", "certificate_identity",
        "certificate_issuer", "uid", "gid", "volumes",
    } or policy["schema"] != "fvca-oci-source-v1":
        raise ValueError("unexpected workload source policy")
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", policy["service"]):
        raise ValueError("invalid service identity")
    if not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}/[a-z0-9._/-]+", policy["repository"]):
        raise ValueError("expected a fully qualified OCI repository")
    if any(part in ("", ".", "..") for part in policy["repository"].split("/")):
        raise ValueError("unexpected OCI repository path")
    for name in ("index", "manifest"):
        digest_hex(policy[name])
    for name in ("certificate_identity", "certificate_issuer"):
        if not re.fullmatch(r"https://[^\s]+", policy[name]):
            raise ValueError("expected an exact HTTPS signing identity and issuer")
    if any(type(policy[key]) is not int or not 0 < policy[key] < 65535 for key in ("uid", "gid")):
        raise ValueError("the workload requires explicit non-root identities")
    volumes = [absolute_path(path) for path in policy["volumes"]]
    if sorted(set(volumes)) != volumes or "/" in volumes:
        raise ValueError("expected sorted, unique data volume paths")
    return policy


def load_policy(path):
    return validate_policy(parse_json(read_bytes(path)))


def descriptor(value, media_types, limit):
    kind, digest, size = (value[field] for field in ("mediaType", "digest", "size"))
    digest_hex(digest)
    if kind not in media_types or type(size) is not int or not 0 < size <= limit:
        raise ValueError("unsupported OCI media type or descriptor size")
    return {"mediaType": kind, "digest": digest, "size": size}


def blob_path(layout, digest):
    return layout / "blobs/sha256" / digest_hex(digest)


def read_blob(layout, spec):
    data = read_bytes(blob_path(layout, spec["digest"]), spec["size"])
    if len(data) != spec["size"] or sha256(data) != spec["digest"]:
        raise ValueError(f"OCI descriptor does not match {spec['digest']}")
    return data


def manifest_object(raw, kind):
    parsed = parse_json(raw)
    if parsed.get("schemaVersion") != 2 or parsed.get("mediaType") != kind:
        raise ValueError("unexpected OCI manifest media type or schema")
    return parsed


def inspect_source(policy, index_raw, layout):
    if sha256(index_raw) != policy["index"]:
        raise ValueError("publisher index does not match the approved digest")
    entries = manifest_object(index_raw, INDEX)["manifests"]
    choices = [
        item for item in entries
        if all(item.get("platform", {}).get(key) == value for key, value in PLATFORM.items())
    ]
    if len(choices) != 1 or choices[0].get("platform", {}).get("variant", "") not in ("", "v1"):
        raise ValueError("publisher index must uniquely select the baseline Linux amd64 manifest")
    selected = descriptor(choices[0], {MANIFEST}, METADATA_LIMIT)
    if selected["digest"] != policy["manifest"]:
        raise ValueError("selected platform manifest differs from the approved digest")

    if not all(path.is_dir() and not path.is_symlink() for path in (layout, layout / "blobs", layout / "blobs/sha256")):
        raise ValueError("invalid OCI layout directories")
    if parse_json(read_bytes(layout / "oci-layout")) != {"imageLayoutVersion": "1.0.0"}:
        raise ValueError("unexpected OCI layout version")
    local = parse_json(read_bytes(layout / "index.json"))
    if local["schemaVersion"] != 2 or [
        descriptor(entry, {MANIFEST}, METADATA_LIMIT) for entry in local["manifests"]
    ] != [selected]:
        raise ValueError("local OCI layout must contain only the selected manifest")
    manifest = manifest_object(read_blob(layout, selected), MANIFEST)
    config = descriptor(manifest["config"], {CONFIG}, METADATA_LIMIT)
    layers = [descriptor(item, LAYER_MEDIA, COMPRESSED_LIMIT) for item in manifest["layers"]]
    if not 1 <= len(layers) <= 32 or sum(layer["size"] for layer in layers) > COMPRESSED_LIMIT:
        raise ValueError("OCI layers exceed conversion limits")
    raw_config = parse_json(read_blob(layout, config))
    if any(raw_config.get(key) != value for key, value in PLATFORM.items()) or raw_config.get("variant", "") not in ("", "v1"):
        raise ValueError("OCI config declares an unexpected platform")
    rootfs = raw_config["rootfs"]
    diffs = rootfs["diff_ids"]
    if rootfs["type"] != "layers" or len(diffs) != len(layers):
        raise ValueError("invalid OCI layer diff IDs")
    for digest in diffs:
        digest_hex(digest)
    return selected, config, layers, diffs, raw_config["config"]


def snapshot_source(policy_path, index_path, layout, destination):
    policy_bytes = read_bytes(policy_path)
    policy = validate_policy(parse_json(policy_bytes))
    index_raw = read_bytes(index_path)
    selected, config, layers, _, _ = inspect_source(policy, index_raw, layout)
    staged = destination / "oci"
    (staged / "blobs/sha256").mkdir(parents=True)
    (destination / "policy.json").write_bytes(policy_bytes)
    (destination / "publisher-index.json").write_bytes(index_raw)
    (staged / "oci-layout").write_bytes(json_bytes({"imageLayoutVersion": "1.0.0"}))
    entry = {**selected, "annotations": {"org.opencontainers.image.ref.name": "source"}}
    (staged / "index.json").write_bytes(json_bytes({"schemaVersion": 2, "mediaType": INDEX, "manifests": [entry]}))
    for spec in (selected, config, *layers):
        digest = spec["digest"]
        destination_blob = blob_path(staged, digest)
        if destination_blob.exists():
            continue
        with open_regular(blob_path(layout, digest)) as original, destination_blob.open("xb") as copy:
            hasher = hashlib.sha256()
            remaining = spec["size"]
            while remaining and (chunk := original.read(min(remaining, 1024 * 1024))):
                copy.write(chunk)
                hasher.update(chunk)
                remaining -= len(chunk)
            if remaining or original.read(1) or f"sha256:{hasher.hexdigest()}" != digest:
                raise ValueError(f"OCI descriptor does not match {digest}")
    return policy
