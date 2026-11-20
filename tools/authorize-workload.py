#!/usr/bin/env python3
"""Reproduce an admitted workload and sign its deployment-bound execution root."""

import argparse
import base64
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
from uuid import UUID, uuid5, NAMESPACE_URL

from image_verity import VERITY_PARTITIONS, read_layout, verify_cms, verify_verity
from workload_build import derive, publish, source_arguments
import workload_oci as oci


ARTIFACT_LIMIT = oci.DECOMPRESSED_LIMIT + 20 * 1024**2
SIGNATURE_LIMIT = 16 * 1024


def sign(content, signature, key, certificate):
    subprocess.run([
        "openssl", "cms", "-sign", "-binary", "-nocerts", "-noattr", "-outform", "DER", "-in", content,
        "-signer", certificate, "-inkey", key, "-out", signature,
    ], check=True)
    verify_cms(content, signature, certificate)


def certificate_info(certificate):
    der = subprocess.check_output(["openssl", "x509", "-in", certificate, "-outform", "DER"])
    key = subprocess.check_output(["openssl", "x509", "-in", certificate, "-pubkey", "-noout"])
    return oci.sha256(der), key


def deployment(args, output):
    record_path = output / "deployment.json"
    signature_path = output / "deployment.p7s"
    raw = oci.read_bytes(args.deployment)
    record_path.write_bytes(raw)
    signature_path.write_bytes(oci.read_bytes(args.deployment_signature, SIGNATURE_LIMIT))
    verify_cms(record_path, signature_path, args.deployment_certificate)
    approved = oci.parse_json(raw)
    if approved.keys() != {
        "schema", "role", "guest", "service", "source_index", "manifest", "provenance", "launch",
        "valid_from", "expires", "security_epoch", "revocation_id", "limits", "network", "id_map",
    } or approved["schema"] != "fvca-workload-deployment-v1":
        raise ValueError("unexpected deployment approval fields")
    if approved["role"] != "service-guest" or approved["provenance"] != "PUBLISHER_VERIFIED":
        raise ValueError("deployment must authorize a publisher-verified Service Guest workload")
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", approved["guest"]):
        raise ValueError("invalid deployment Guest identity")
    for key in ("source_index", "manifest", "launch"):
        oci.digest_hex(approved[key])
    if str(UUID(approved["revocation_id"])) != approved["revocation_id"]:
        raise ValueError("invalid deployment revocation identity")
    if any(type(approved[field]) is not int for field in ("valid_from", "expires", "security_epoch")):
        raise ValueError("deployment validity and epoch must be integers")
    if not 0 <= approved["valid_from"] <= int(time.time()) < approved["expires"] < 2**63:
        raise ValueError("deployment approval is outside its validity period")
    if not 0 < approved["security_epoch"] < 2**63:
        raise ValueError("invalid deployment epoch")
    network = approved["network"]
    if network != "none":
        if not isinstance(network, dict) or network.keys() != {"workload"}:
            raise ValueError("expected a networkless workload or the digest of its Guest network record")
        oci.digest_hex(network["workload"])
    mapping = approved["id_map"]
    if mapping.keys() != {"uid_base", "gid_base", "size"} or type(mapping["size"]) is not int or mapping["size"] != 65536:
        raise ValueError("deployment requires a complete 16-bit container ID range")
    if any(type(mapping[key]) is not int or not 65536 <= mapping[key] < 2**32 - mapping["size"]
           for key in ("uid_base", "gid_base")):
        raise ValueError("deployment ID range must use subordinate host identities")
    bounds = {"memory_bytes": (32 * 1024**2, 64 * 1024**3), "cpu_percent": (1, 6400), "pids": (1, 4096)}
    if approved["limits"].keys() != bounds.keys() or any(
        type(approved["limits"][key]) is not int or not low <= approved["limits"][key] <= high
        for key, (low, high) in bounds.items()
    ):
        raise ValueError("deployment resource limits are missing or outside the supported range")
    return approved, oci.sha256(raw)


def check_replay(candidate, replay):
    for name, limit in (
        ("root.erofs", oci.DECOMPRESSED_LIMIT), ("verity.hash", 16 * 1024**2), ("roothash", 64),
        ("launch.json", oci.METADATA_LIMIT), ("derivation.json", oci.METADATA_LIMIT),
    ):
        if oci.file_record(candidate / name, limit) != oci.file_record(replay / name, limit):
            raise ValueError(f"candidate {name} differs from the independent derivation")


def assemble_image(image, replay, root_hash, signature_payload):
    sector_size = 512
    alignment = 2048
    signature = replay / "signature.json"
    signature.write_bytes(signature_payload)
    if not 0 < signature.stat().st_size <= SIGNATURE_LIMIT:
        raise ValueError("workload signature partition is too large")
    source = (
        ("root", replay / "root.erofs", UUID(hex=root_hash[:32])),
        ("verity", replay / "verity.hash", UUID(hex=root_hash[32:])),
        ("signature", signature, uuid5(NAMESPACE_URL, f"fvca:workload:signature:{root_hash}")),
    )
    disk_id = uuid5(NAMESPACE_URL, f"fvca:workload:disk:{root_hash}")
    lines = ["label: gpt", f"label-id: {disk_id}", "unit: sectors"]
    start = alignment
    writes = []
    for name, path, identity in source:
        size = SIGNATURE_LIMIT if name == "signature" else path.stat().st_size
        if not size or size % 4096:
            raise ValueError("workload partition is not block-aligned")
        sectors = size // sector_size
        lines.append(f'start={start}, size={sectors}, type={VERITY_PARTITIONS[name]}, uuid={identity}, name="{name}"')
        writes.append((start * sector_size, path))
        start = (start + sectors + alignment - 1) // alignment * alignment
    with image.open("xb") as disk:
        disk.truncate((start + alignment) * sector_size)
    subprocess.run(
        ["sfdisk", "--no-reread", "--no-tell-kernel", "--quiet", image],
        input=("\n".join(lines) + "\n").encode("ascii"), check=True,
    )
    with image.open("r+b") as disk:
        for offset, path in writes:
            disk.seek(offset)
            with oci.open_regular(path) as content:
                shutil.copyfileobj(content, disk, length=1024 * 1024)


def authorize(args, work, output):
    output.mkdir(mode=0o700)
    approved, deployment_digest = deployment(args, output)
    deploy_fingerprint, deploy_key = certificate_info(args.deployment_certificate)
    root_fingerprint, root_key = certificate_info(args.workload_certificate)
    if deploy_key == root_key:
        raise ValueError("deployment and workload authorization require separate keys")

    replay = work / "replay"
    evidence = derive(args, replay)
    check_replay(args.candidate, replay)
    if (
        approved["service"], approved["source_index"], approved["manifest"], approved["launch"],
    ) != (evidence["service"], evidence["source"]["index"], evidence["manifest"]["digest"], evidence["launch"]):
        raise ValueError("deployment approves a different workload source or launch definition")
    if not approved["valid_from"] <= int(time.time()) < approved["expires"]:
        raise ValueError("deployment approval expired during derivation")

    root_hash = evidence["verity_root_hash"]
    signature = replay / "root.p7s"
    sign(replay / "roothash", signature, args.workload_key, args.workload_certificate)
    signature_payload = oci.json_bytes({
        "rootHash": root_hash, "certificateFingerprint": oci.digest_hex(root_fingerprint),
        "signature": base64.b64encode(oci.read_bytes(signature, SIGNATURE_LIMIT)).decode("ascii"),
    })
    image = output / "workload.raw"
    assemble_image(image, replay, root_hash, signature_payload)
    verification = work / "verification"
    verification.mkdir()
    sector_size, partitions = read_layout(image, VERITY_PARTITIONS)
    verify_verity(image, sector_size, partitions, args.workload_certificate, verification, root_hash)
    if (
        oci.file_record(verification / "root", oci.DECOMPRESSED_LIMIT) != evidence["root"]
        or oci.file_record(verification / "verity", 16 * 1024**2) != evidence["verity_tree"]
    ):
        raise ValueError("assembled partition contents differ from the verified derivation")

    for name in ("launch.json", "derivation.json", "publisher-proof.json"):
        (output / name).write_bytes(oci.read_bytes(replay / name))
    authorization = {
        "schema": "fvca-workload-authorization-v1",
        "deployment": deployment_digest, "deployment_certificate": deploy_fingerprint,
        "workload_certificate": root_fingerprint,
        "derivation": oci.sha256(oci.read_bytes(output / "derivation.json")),
        "publisher_proof": oci.sha256(oci.read_bytes(output / "publisher-proof.json")),
        "artifact": oci.file_record(image, ARTIFACT_LIMIT),
        "verity_root_hash": root_hash,
    }
    record = output / "authorization.json"
    record.write_bytes(oci.json_bytes(authorization))
    if int(time.time()) >= approved["expires"]:
        raise ValueError("deployment approval expired before signing")
    sign(record, output / "authorization.p7s", args.workload_key, args.workload_certificate)
    return approved, authorization["artifact"]["digest"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source_arguments(parser)
    for name in (
        "candidate", "deployment", "deployment-signature", "deployment-certificate",
        "workload-key", "workload-certificate",
    ):
        parser.add_argument(f"--{name}", type=lambda value: Path(value).absolute(), required=True)
    args = parser.parse_args()
    try:
        with tempfile.TemporaryDirectory(prefix=".fvca-authorize-", dir=args.output.parent) as directory:
            work = Path(directory)
            output = work / "authorized"
            approved, artifact = authorize(args, work, output)
            publish(output, args.output)
        print(f"Authorized {approved['service']} for {approved['guest']} at {artifact}")
    except (OSError, ValueError, TypeError, KeyError, IndexError, subprocess.SubprocessError) as error:
        parser.exit(1, f"FVCA workload authorization failed: {error}\n")


if __name__ == "__main__":
    main()
