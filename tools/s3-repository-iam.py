#!/usr/bin/env python3
"""Render a scoped IAM identity policy for one FVCA S3 repository role."""

import argparse
import json
from pathlib import Path

import backup_destination


def policy(destination, role):
    bucket = f"arn:aws:s3:::{destination.bucket}"
    root = f"{bucket}/{destination.prefix}/" if destination.prefix else f"{bucket}/"
    packs = ["data/*", "index/*"]
    locks = ["locks/*"]
    history = ["snapshots/*"]

    statements = [
        {"Effect": "Allow", "Action": ["s3:GetBucketLocation"], "Resource": [bucket]},
        {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": [bucket]},
    ]
    if destination.prefix:
        statements[-1]["Condition"] = {"StringLike": {"s3:prefix": [destination.prefix, f"{destination.prefix}/*"]}}

    def allow(actions, members):
        statements.append({"Effect": "Allow", "Action": actions, "Resource": [root + item for item in members]})

    allow(["s3:GetObject"], ["config", "keys/*", *packs, *locks, *history])
    if role in {"upload", "audit", "maintenance"}:
        allow(["s3:PutObject", "s3:DeleteObject"], locks)
    if role in {"upload", "maintenance"}:
        writable = [*packs, *history] if role == "upload" else packs
        allow(["s3:PutObject", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"], writable)
    if role == "maintenance":
        allow(["s3:DeleteObject"], [*packs, *history])
    return {"Version": "2012-10-17", "Statement": statements}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--ca", type=Path, required=True)
    parser.add_argument("role", choices=("upload", "audit", "restore", "maintenance"))
    args = parser.parse_args()
    try:
        destination = backup_destination.parse(args.destination.read_bytes(), args.ca.read_bytes())
        print(json.dumps(policy(destination, args.role), indent=2))
    except (OSError, ValueError) as error:
        parser.exit(1, f"FVCA S3 IAM policy failed: {error}\n")


if __name__ == "__main__":
    main()
