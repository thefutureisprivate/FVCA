#!/usr/bin/env python3
"""Boot a signed Guest and qualify its enrolled HTTPS workload delivery."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile


TESTS = Path(__file__).resolve().parent


def check(args):
    sys.path.insert(0, str(TESTS.parent / "tools"))
    from guest_boot_bundle import verify

    storage = runpy.run_path(str(TESTS / "check-storage.py"))
    https = runpy.run_path(str(TESTS / "check-release-https.py"))
    command_line, _ = verify(args.bundle, args.release_certificate)
    args.output.mkdir(mode=0o700)
    grant = args.grant.read_bytes()
    record = json.loads(grant)
    digest = f"sha256:{hashlib.sha256(grant).hexdigest()}".encode()
    client = argparse.Namespace(
        guest=True, direct_boot=args.bundle, direct_cmdline=command_line,
        disk=args.bundle / "core.raw", runtime=args.bundle / "runtime.raw",
        output=args.output, persistent_members=True,
    )
    delivered = b"FVCA_WORKLOAD_CHANNEL_DELIVERED " + digest
    committed = b"FVCA_WORKLOAD_TRIAL_COMMITTED " + digest + b" " + record["to_authorization"].encode()
    with tempfile.TemporaryDirectory(prefix=".workload-channel-guest-", dir=args.output) as scratch:
        data = Path(scratch) / "guest-data.raw"
        subprocess.run(["cp", "--reflink=auto", "--sparse=always", "--", args.data, data], check=True)
        with https["serve"](args.depot, (args.tls_certificate, args.tls_key), ("10.0.2.100", 443)) as depot:
            if args.interrupt_delivery:
                prompts, first = storage["boot"](
                    client, "channel-interrupted", None, data, timeout=190, ready_marker=delivered,
                    workload_depot_tap=True,
                )
                if prompts or delivered not in storage["rejoin_serial_output"](first) or committed in first:
                    raise ValueError("the interruption did not occur after delivery and before commit")
            prompts, output = storage["boot"](
                client, "channel-delivery", None, data, timeout=250, ready_marker=committed,
                workload_depot_tap=True,
            )
            image_requests = sum(path.endswith("-workload.raw") for path in depot.requests)
            total_requests = len(depot.requests)
            handshake_failures = depot.handshake_failures
    output = storage["rejoin_serial_output"](output)
    started = output.find(b"FVCA_WORKLOAD_TRIAL_STARTED " + digest)
    if args.interrupt_delivery:
        reauthorized = output.find(b"FVCA_WORKLOAD_CHANNEL_REAUTHORIZED " + digest)
        ordered = 0 <= reauthorized < started < output.find(committed)
    else:
        delivery = output.find(delivered)
        stage = output.find(b"FVCA_WORKLOAD_STAGED published " + digest)
        ordered = 0 <= delivery < stage < started < output.find(committed)
    if (prompts or storage["FAIL"] in output or storage["DIRECT_ACTIVE"] not in output
            or image_requests != 1 or not ordered
            or b"FVCA_STALWART_MAIL_VERIFIED" not in output):
        raise ValueError("the signed Guest did not discover, deliver, stage and commit its exact HTTPS offer "
                         f"({total_requests} HTTPS requests, {image_requests} image requests, "
                         f"TLS errors {handshake_failures})")
    print("workload-channel-reauthorize passed" if args.interrupt_delivery else "workload-channel-signed-boot passed")


def main():
    namespace = str(os.stat("/proc/self/ns/net").st_ino)
    if sys.argv[1:2] != ["--isolated-from"]:
        os.execvp("unshare", [
            "unshare", "--user", "--map-root-user", "--net",
            sys.executable, "-B", str(Path(__file__).resolve()),
            "--isolated-from", namespace, *sys.argv[1:],
        ])
    if sys.argv[2] == namespace:
        raise SystemExit("The workload depot requires a new isolated network namespace")
    del sys.argv[1:3]
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("bundle", "release-certificate", "data", "grant", "depot", "tls-certificate", "tls-key", "output"):
        parser.add_argument(f"--{name}", required=True, type=lambda path: Path(path).absolute())
    parser.add_argument("--interrupt-delivery", action="store_true")
    try:
        args = parser.parse_args()
        subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
        subprocess.run(["ip", "tuntap", "add", "dev", "fvca-depot", "mode", "tap"], check=True)
        subprocess.run(["ip", "addr", "add", "10.0.2.100/24", "dev", "fvca-depot"], check=True)
        subprocess.run(["ip", "link", "set", "dev", "fvca-depot", "up"], check=True)
        check(args)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Workload channel boot qualification failed: {error}\n")


if __name__ == "__main__":
    main()
