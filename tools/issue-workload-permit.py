#!/usr/bin/env python3
"""Issue one signed unsigned-source permit from a scoped operator acknowledgment."""

import argparse
from http.client import HTTPException
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from uuid import UUID

from image_verity import verify_cms
from workload_build import publish
from workload_discovery import discover
import workload_oci as oci


LIMIT = 16 * 1024
ACKNOWLEDGMENT = "I KNOW THIS MIGHT BE INSECURE"
OPERATOR_ROLE = "workload-unsigned-approver"
DELEGATION_FIELDS = {
    "schema", "operator", "operator_certificate", "role", "guest", "service", "repository",
    "source_policy", "valid_from", "expires", "max_permit_seconds", "registry_token_service",
}
REQUEST_FIELDS = {
    "schema", "operator", "role", "guest", "service", "repository", "source_policy", "source_index",
    "manifest", "platform", "launch", "acknowledgment", "reason", "requested_at", "expires",
    "revocation_id", "revocation_action",
}


def snapshot(source, destination, limit=LIMIT):
    data = oci.read_bytes(source, limit)
    destination.write_bytes(data)
    return data


def certificate_identity(path):
    der = subprocess.check_output(["openssl", "x509", "-in", path, "-outform", "DER"], timeout=10)
    public_key = subprocess.check_output(["openssl", "x509", "-in", path, "-pubkey", "-noout"], timeout=10)
    return oci.sha256(der), public_key


def check_time(delegation, request, now):
    if not (
        0 < delegation["valid_from"] <= request["requested_at"] <= now < request["expires"]
        <= delegation["expires"] < 2**63
        and 0 < request["expires"] - request["requested_at"] <= delegation["max_permit_seconds"] < 2**63
    ):
        raise ValueError("operator delegation or requested permit is outside its authorized lifetime")


def check_acknowledgment(delegation, request, policy, policy_digest, launch):
    if (not isinstance(delegation, dict) or delegation.keys() != DELEGATION_FIELDS
            or delegation["schema"] != "fvca-workload-permit-delegation-v1"
            or not isinstance(request, dict) or request.keys() != REQUEST_FIELDS
            or request["schema"] != "fvca-workload-permit-request-v1"):
        raise ValueError("unexpected delegation or acknowledgment fields")
    if any(not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", request[field]) for field in ("operator", "guest")):
        raise ValueError("invalid operator or Guest identity")
    if (any(request[field] != delegation[field]
            for field in ("operator", "guest", "service", "repository", "source_policy", "role"))
            or request["role"] != OPERATOR_ROLE):
        raise ValueError("acknowledgment is outside the operator delegation")

    expected = {
        "repository": policy["repository"], "service": policy["service"], "source_policy": policy_digest,
        "source_index": policy["index"], "manifest": policy["manifest"], "platform": oci.PLATFORM,
        "launch": oci.sha256(launch), "acknowledgment": ACKNOWLEDGMENT,
    }
    if any(request[field] != value for field, value in expected.items()):
        raise ValueError("acknowledgment does not bind the exact source, platform, launch and warning")
    reason = request["reason"]
    if not isinstance(reason, str) or not 1 <= len(reason) <= 512 or not reason.isprintable() or reason.strip() != reason:
        raise ValueError("provide an auditable reason for this exact deployment")
    if (not isinstance(request["revocation_id"], str) or str(UUID(request["revocation_id"])) != request["revocation_id"]
            or request["revocation_action"] not in ("block-new-starts", "stop")):
        raise ValueError("invalid permit revocation identity or action")
    if (any(type(delegation[field]) is not int for field in ("valid_from", "expires", "max_permit_seconds"))
            or any(type(request[field]) is not int for field in ("requested_at", "expires"))):
        raise ValueError("delegation and permit times must be integer Unix seconds")


def exception_policy(raw):
    policy = oci.parse_json(raw)
    if (not isinstance(policy, dict) or policy.keys() != oci.SOURCE_FIELDS | {"permit_authority"}
            or policy["schema"] != "fvca-oci-explicit-exceptions-v1"):
        raise ValueError("source policy does not explicitly permit unsigned exceptions")
    oci.digest_hex(policy["permit_authority"])
    return oci.validate_source_scope(policy)


def preview_launch(args, policy):
    _, _, _, _, config = oci.inspect_source(policy, oci.read_bytes(args.source_index), args.layout)
    return oci.json_bytes(oci.launch_metadata(policy, config))


def issue(args, output):
    output.mkdir(mode=0o700)
    policy_raw = snapshot(args.policy, output / "source-policy.json", oci.METADATA_LIMIT)
    policy = exception_policy(policy_raw)
    authority_certificate = output / "authority.crt"
    operator_certificate = output / "operator.crt"
    snapshot(args.authority_certificate, authority_certificate)
    snapshot(args.operator_certificate, operator_certificate)
    authority_digest, authority_key = certificate_identity(authority_certificate)
    operator_digest, operator_key = certificate_identity(operator_certificate)
    if policy["permit_authority"] != authority_digest or authority_key == operator_key:
        raise ValueError("permit issuer and operator must use their distinct pinned keys")

    delegation_record = output / "delegation.json"
    delegation_signature = output / "delegation.p7s"
    delegation_raw = snapshot(args.delegation, delegation_record)
    snapshot(args.delegation_signature, delegation_signature)
    verify_cms(delegation_record, delegation_signature, authority_certificate)
    request_record = output / "request.json"
    request_signature = output / "request.p7s"
    request_raw = snapshot(args.request, request_record)
    snapshot(args.request_signature, request_signature)
    verify_cms(request_record, request_signature, operator_certificate)
    delegation = oci.parse_json(delegation_raw)
    request = oci.parse_json(request_raw)
    launch = snapshot(args.launch, output / "launch.json", oci.METADATA_LIMIT)
    check_acknowledgment(delegation, request, policy, oci.sha256(policy_raw), launch)
    if delegation["operator_certificate"] != operator_digest:
        raise ValueError("operator certificate differs from the signed delegation")
    check_time(delegation, request, int(time.time()))

    # Check the selected platform and actual OCI metadata before the registry observation.
    if launch != preview_launch(args, policy):
        raise ValueError("reviewed launch differs from the normalized OCI source")
    observation = discover(policy, delegation["registry_token_service"])
    issued_at = int(time.time())
    check_time(delegation, request, issued_at)
    permit = {
        "schema": "fvca-workload-unsigned-permit-v1", "provenance": "UNSIGNED_UPSTREAM_APPROVED",
        "acknowledgment": request, "request_sha256": oci.sha256(request_raw),
        "operator_certificate": operator_digest, "delegation_sha256": oci.sha256(delegation_raw),
        "issued_at": issued_at, "discovery": observation, "expiry_action": "block-new-starts",
    }
    record = output / "permit.json"
    record.write_bytes(oci.json_bytes(permit))
    signature = output / "permit.p7s"
    subprocess.run([
        "openssl", "cms", "-sign", "-binary", "-nocerts", "-noattr", "-outform", "DER", "-in", record,
        "-signer", authority_certificate, "-inkey", args.authority_key, "-out", signature,
    ], check=True, timeout=30)
    oci.read_bytes(signature, LIMIT)
    verify_cms(record, signature, authority_certificate)
    check_time(delegation, request, int(time.time()))
    return request["revocation_id"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    preview = commands.add_parser("preview", help="print the normalized launch for the operator to review")
    issuer = commands.add_parser("issue", help="verify the signed acknowledgment and issue a permit")
    for command in (preview, issuer):
        for name in ("policy", "source-index", "layout"):
            command.add_argument(f"--{name}", required=True, type=Path)
    for name in ("launch", "operator-certificate", "request", "request-signature", "authority-certificate",
                 "authority-key", "delegation", "delegation-signature", "output"):
        issuer.add_argument(f"--{name}", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.command == "preview":
            policy = exception_policy(oci.read_bytes(args.policy))
            sys.stdout.buffer.write(preview_launch(args, policy))
            return
        with tempfile.TemporaryDirectory(prefix=".fvca-unsigned-permit-", dir=args.output.parent) as temporary:
            output = Path(temporary) / "permit"
            identity = issue(args, output)
            publish(output, args.output)
        print(f"FVCA_UNSIGNED_PERMIT_ISSUED {identity}")
    except (OSError, ValueError, TypeError, KeyError, IndexError, HTTPException, subprocess.SubprocessError) as error:
        parser.exit(1, f"FVCA unsigned workload permit rejected: {error}\n")


if __name__ == "__main__":
    main()
