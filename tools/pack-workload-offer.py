#!/usr/bin/env python3
"""Prepare exact workload channel targets for a separately signed TUF repository."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time


MEMBERS = (
    "transition.json", "transition.p7s",
    "candidate/authorization.json", "candidate/authorization.p7s",
    "candidate/deployment.json", "candidate/deployment.p7s", "candidate/derivation.json",
    "candidate/launch.json", "candidate/publisher-proof.json", "candidate/workload.raw",
)


def prepare(args, scratch):
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", args.channel) or not 0 < args.sequence < 2**64:
        raise ValueError("expected a canonical channel and positive sequence")
    now = int(time.time())
    if not 0 < args.valid_from <= now < args.expires or args.expires - args.valid_from > 604800:
        raise ValueError("expected a current channel head valid for at most seven days")
    if args.output.exists():
        raise ValueError("the workload target output already exists")

    copy = scratch / "transition"
    (copy / "candidate").mkdir(parents=True, mode=0o700)
    for name in MEMBERS:
        source = args.transition / name
        if source.is_symlink() or not source.is_file() or not 0 < source.stat().st_size <= 660 * 1024**2:
            raise ValueError(f"expected a bounded regular transition member at {name}")
        subprocess.run(["cp", "--reflink=auto", "--", source, copy / name], check=True)
    subprocess.run([
        args.verifier, "--verify-transition", args.current_policy, args.deployment_certificate,
        args.workload_certificate, args.current, copy / "candidate",
        copy / "transition.json", copy / "transition.p7s",
    ], check=True)

    grant = (copy / "transition.json").read_bytes()
    record = json.loads(grant)
    grant_digest = hashlib.sha256(grant).hexdigest()
    for field in ("guest", "service"):
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", record[field]):
            raise ValueError(f"invalid signed workload {field}")
    expires = min(args.expires, record["expires"])
    if expires <= now:
        raise ValueError("the signed transition would expire before publication")
    head = {
        "schema": "fvca-workload-channel-head-v1", "guest": record["guest"], "service": record["service"],
        "channel": args.channel, "sequence": args.sequence, "valid_from": args.valid_from, "expires": expires,
        "release": {"from_authorization": record["from_authorization"],
                    "to_authorization": record["to_authorization"], "transition_sha256": grant_digest},
    }
    ready = scratch / "targets"
    ready.mkdir(mode=0o700)
    for name in MEMBERS:
        (copy / name).rename(ready / f"fvca-workload-{grant_digest}-{Path(name).name}")
    filename = f"fvca-workload.{record['guest']}.{record['service']}.{args.channel}.json"
    (ready / filename).write_text(json.dumps(head, sort_keys=True, separators=(",", ":")) + "\n", encoding="ascii")
    ready.rename(args.output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("verifier", "current-policy", "deployment-certificate", "workload-certificate",
                 "current", "transition", "output"):
        parser.add_argument(f"--{name}", required=True, type=lambda value: Path(value).absolute())
    parser.add_argument("--channel", required=True)
    for name in ("sequence", "valid-from", "expires"):
        parser.add_argument(f"--{name}", type=int, required=True)
    args = parser.parse_args()
    try:
        with tempfile.TemporaryDirectory(prefix=".fvca-workload-offer-", dir=args.output.parent) as work:
            prepare(args, Path(work))
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"FVCA workload channel preparation failed: {error}\n")


if __name__ == "__main__":
    main()
