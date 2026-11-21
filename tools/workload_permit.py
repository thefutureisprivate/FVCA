"""Validate the immutable unsigned-source admission record off-node."""

import base64
import re
import subprocess
import time
from uuid import UUID

from image_verity import verify_cms
import workload_oci as oci


LIMIT = 16 * 1024
ACKNOWLEDGMENT = "I KNOW THIS MIGHT BE INSECURE"
OPERATOR_ROLE = "workload-unsigned-approver"
UNSIGNED = "UNSIGNED_UPSTREAM_APPROVED"
PUBLISHER = "PUBLISHER_VERIFIED"
REQUEST_FIELDS = {
    "schema", "operator", "role", "guest", "service", "repository", "source_policy", "source_index",
    "manifest", "platform", "launch", "acknowledgment", "reason", "requested_at", "expires",
    "revocation_id", "revocation_action",
}


def certificate(path):
    der = subprocess.check_output(["openssl", "x509", "-in", path, "-outform", "DER"], timeout=10)
    public_key = subprocess.check_output(["openssl", "x509", "-in", path, "-pubkey", "-noout"], timeout=10)
    return der, public_key


def portable(raw):
    return base64.b64encode(raw).decode("ascii")


def check_request(request, policy, policy_digest, launch):
    if (not isinstance(request, dict) or request.keys() != REQUEST_FIELDS
            or request["schema"] != "fvca-workload-permit-request-v1"):
        raise ValueError("unexpected unsigned-source acknowledgment fields")
    if any(not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", request[field]) for field in ("operator", "guest")):
        raise ValueError("invalid operator or Guest identity")
    expected = {
        "repository": policy["repository"], "service": policy["service"], "source_policy": policy_digest,
        "source_index": policy["index"], "manifest": policy["manifest"], "platform": oci.PLATFORM,
        "launch": oci.sha256(launch), "acknowledgment": ACKNOWLEDGMENT, "role": OPERATOR_ROLE,
    }
    if any(request[field] != value for field, value in expected.items()):
        raise ValueError("acknowledgment does not bind the exact source, platform, launch, role and warning")
    reason = request["reason"]
    if not isinstance(reason, str) or not 1 <= len(reason) <= 512 or not reason.isprintable() or reason.strip() != reason:
        raise ValueError("provide an auditable reason for this exact deployment")
    if (not isinstance(request["revocation_id"], str) or str(UUID(request["revocation_id"])) != request["revocation_id"]
            or request["revocation_action"] not in ("block-new-starts", "stop")):
        raise ValueError("invalid permit revocation identity or action")
    if any(type(request[field]) is not int for field in ("requested_at", "expires")):
        raise ValueError("permit times must be integer Unix seconds")


def check_discovery(observation, policy):
    if (not isinstance(observation, dict) or observation.keys() != {"schema", "repository", "subjects"}
            or observation["schema"] != "fvca-signature-discovery-v1"
            or observation["repository"] != policy["repository"]
            or [subject["digest"] for subject in observation["subjects"]] != [policy["index"], policy["manifest"]]):
        raise ValueError("permit lacks complete signature discovery for the exact source")
    probes = {"referrers_api": (200, 404), "referrers_tag": (200, 404), "cosign_signature_tag": (404,)}
    for subject in observation["subjects"]:
        if subject.keys() != probes.keys() | {"digest"}:
            raise ValueError("permit lacks a required signature discovery probe")
        for name, statuses in probes.items():
            result = subject[name]
            if (not isinstance(result, dict) or result.keys() != {"status", "response"}
                    or result["status"] not in statuses):
                raise ValueError("permit did not record a successful absence check")
            oci.digest_hex(result["response"])


def verify(source, policy, policy_raw, launch, staged):
    paths = {name: staged / name for name in ("permit.json", "permit.p7s", "authority.crt")}
    for name, destination in paths.items():
        destination.write_bytes(oci.read_bytes(source / name, LIMIT))
    der, key = certificate(paths["authority.crt"])
    if oci.sha256(der) != policy["permit_authority"]:
        raise ValueError("unsigned permit issuer differs from the reviewed source authority")
    verify_cms(paths["permit.json"], paths["permit.p7s"], paths["authority.crt"])
    raw = oci.read_bytes(paths["permit.json"], LIMIT)
    permit = oci.parse_json(raw)
    if (not isinstance(permit, dict) or permit.keys() != {"schema", "provenance", "acknowledgment", "request_sha256",
            "operator_certificate", "delegation_sha256", "issued_at", "discovery", "expiry_action"}
            or permit["schema"] != "fvca-workload-unsigned-permit-v1" or permit["provenance"] != UNSIGNED
            or permit["expiry_action"] != "block-new-starts"):
        raise ValueError("unexpected unsigned workload permit")
    for field in ("request_sha256", "operator_certificate", "delegation_sha256"):
        oci.digest_hex(permit[field])
    request = permit["acknowledgment"]
    check_request(request, policy, oci.sha256(policy_raw), launch)
    issued = permit["issued_at"]
    if type(issued) is not int or not 0 < request["requested_at"] <= issued <= int(time.time()) < request["expires"] < 2**63:
        raise ValueError("unsigned workload permit is outside its validity period")
    check_discovery(permit["discovery"], policy)
    proof = {
        "provenance": UNSIGNED, "policy": portable(policy_raw), "permit": portable(raw),
        "signature": portable(oci.read_bytes(paths["permit.p7s"], LIMIT)), "authority": portable(der),
    }
    return proof, request, key
