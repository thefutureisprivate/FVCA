#!/usr/bin/env python3
"""Sign a permanent revocation for one authenticated unsigned-source permit."""

import argparse
from pathlib import Path
import subprocess
import tempfile
import time

from image_verity import verify_cms
from workload_build import publish
import workload_oci as oci
from workload_permit import LIMIT, portable, read_signed_permit


def revoke(args, work):
    if not 1 <= len(args.reason) <= 512 or not args.reason.isprintable() or args.reason.strip() != args.reason:
        raise ValueError("provide an auditable reason for this exact revocation")
    policy_raw = oci.read_bytes(args.permit / "source-policy.json")
    policy = oci.validate_exception_policy(oci.parse_json(policy_raw))
    launch = oci.read_bytes(args.permit / "launch.json")
    _, permit, _ = read_signed_permit(args.permit, policy, policy_raw, launch, work)
    request = permit["acknowledgment"]
    revoked_at = int(time.time())
    if not permit["issued_at"] <= revoked_at < 2**63:
        raise ValueError("the authority clock precedes the permit issuance")
    digest = oci.sha256(oci.read_bytes(work / "permit.json", LIMIT))
    record = work / "revocation.json"
    signature = work / "revocation.p7s"
    record.write_bytes(oci.json_bytes({
        "schema": "fvca-workload-permit-revocation-v1", "guest": request["guest"], "service": request["service"],
        "permit_id": request["revocation_id"], "permit": digest, "action": args.action,
        "revoked_at": revoked_at, "reason": args.reason,
    }))
    certificate = work / "authority.crt"
    subprocess.run([
        "openssl", "cms", "-sign", "-binary", "-nocerts", "-noattr", "-outform", "DER", "-in", record,
        "-signer", certificate, "-inkey", args.authority_key, "-out", signature,
    ], check=True, timeout=30)
    verify_cms(record, signature, certificate)
    output = work / "delivery"
    output.mkdir(mode=0o700)
    suffix = "stop" if args.action == "stop" else "block"
    filename = f"{oci.digest_hex(digest)}.{suffix}.json"
    envelope = output / filename
    envelope.write_bytes(oci.json_bytes({"record": portable(oci.read_bytes(record, LIMIT)),
                                         "signature": portable(oci.read_bytes(signature, LIMIT))}))
    envelope.chmod(0o400)
    publish(output, args.output)
    return filename


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("permit", "authority-key", "output"):
        parser.add_argument(f"--{name}", required=True, type=Path)
    parser.add_argument("--action", required=True, choices=("block-new-starts", "stop"))
    parser.add_argument("--reason", required=True)
    args = parser.parse_args()
    try:
        with tempfile.TemporaryDirectory(prefix=".fvca-workload-revocation-", dir=args.output.parent) as temporary:
            filename = revoke(args, Path(temporary))
        print(f"FVCA_WORKLOAD_PERMIT_REVOCATION_SIGNED {filename}")
    except (OSError, ValueError, TypeError, KeyError, IndexError, subprocess.SubprocessError) as error:
        parser.exit(1, f"FVCA permit revocation rejected: {error}\n")


if __name__ == "__main__":
    main()
