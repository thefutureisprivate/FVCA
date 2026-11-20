#!/usr/bin/env python3
"""Check the read-only floor approval against an installed same-epoch Hypervisor pair."""

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


MARKER = b"FVCA_HYPERVISOR_FLOOR_APPROVAL_VERIFIED "


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def qualify(args):
    gpt = runpy.run_path(Path(__file__).with_name("check-hypervisor-gpt-install.py"))
    args.output.mkdir(mode=0o700)
    signing_key = Ed25519PrivateKey.generate()
    authority = args.output / "authority.pub"
    authority.write_bytes(signing_key.public_key().public_bytes_raw())
    unrelated = args.output / "unrelated.pub"
    unrelated.write_bytes(Ed25519PrivateKey.generate().public_key().public_bytes_raw())

    def disk_record(path):
        return json.loads(subprocess.check_output([args.client, "--inspect-hypervisor-gpt", path, "4096"]))

    def approved_slot(media, selection, evidence):
        release = json.loads((args.installer / f"{selection}-selection.json").read_text(encoding="utf-8"))
        files = [file for file in args.boot_evidence.glob(f"{evidence}-*.log")
                 if b"FVCA_HOST_STORAGE_TPM_UNLOCKED" in file.read_bytes()]
        assert len(files) == 1
        return {"disk": disk_record(args.installer / media), "epoch": release["epoch"],
                "manifest_sha256": release["manifest_sha256"], "boot_evidence_sha256": digest(files[0])}

    primary = approved_slot("active.raw", "stage-recovery", "paired-slot-a-initial-floor")
    recovery = approved_slot("inactive.raw", "install-after-interruption", "paired-slot-b-initial-floor")
    assert primary["epoch"] == recovery["epoch"] > 1
    now = int(time.time())
    plan = {"schema": "fvca-hypervisor-floor-approval-v1", "valid_from": now - 60, "expires": now + 1800,
            "sector_size": 4096, "secure_boot_certificate_sha256": digest(args.certificate),
            "epoch_policy_sha256": args.epoch_policy_sha256, "previous_floor": primary["epoch"] - 1,
            "next_floor": primary["epoch"], "primary": primary, "recovery": recovery}

    def run(name, approval, *, failure=None, trusted_authority=authority, certificate=args.certificate, tamper=False):
        document = args.output / f"{name}.json"
        signature = args.output / f"{name}.sig"
        payload = json.dumps(approval, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
        signature.write_bytes(signing_key.sign(payload))
        document.write_bytes(payload + (b" " if tamper else b""))
        result = subprocess.run([args.client, "--verify-hypervisor-floor-approval", args.installer / "cache", document,
                                 signature, trusted_authority, certificate],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
        (args.output / f"{name}.log").write_bytes(result.stdout)
        if failure is None:
            receipt = f"{approval['previous_floor']} {approval['next_floor']} {digest(document)}\n".encode("ascii")
            assert result.returncode == 0 and result.stdout == MARKER + receipt, result.stdout
        else:
            assert result.returncode != 0 and failure in result.stdout and MARKER not in result.stdout, result.stdout
        print(f"{name} passed", flush=True)

    run("approved-pair", plan)
    signature_error = b"independent Hypervisor floor approval signature is invalid"
    run("tampered-approval", plan, tamper=True, failure=signature_error)
    run("wrong-authority", plan, trusted_authority=unrelated, failure=signature_error)
    run("expired", plan | {"valid_from": now - 60, "expires": now - 1}, failure=b"validity interval is invalid")
    run("unbounded-validity", plan | {"expires": now + 86400}, failure=b"validity interval is invalid")
    run("counter-skip", plan | {"next_floor": plan["next_floor"] + 1}, failure=b"one TPM counter step")
    run("old-recovery", plan | {"recovery": recovery | {"epoch": primary["epoch"] - 1}},
        failure=b"both reviewed boot paths must meet the next floor")
    run("duplicate-evidence", plan | {"recovery": recovery | {"boot_evidence_sha256": primary["boot_evidence_sha256"]}},
        failure=b"requires independent primary and recovery boot paths")
    wrong_cert = args.output / "unapproved.crt"
    wrong_cert.write_bytes(args.certificate.read_bytes() + b"\n")
    run("wrong-certificate", plan, certificate=wrong_cert, failure=b"certificate differs")
    alternate = ("a" if args.epoch_policy_sha256.startswith("b") else "b") * 64
    run("wrong-enrollment", plan | {"epoch_policy_sha256": alternate}, failure=b"TPM policy differs from the reviewed enrollment")

    copied = gpt["clone"](args.installer / "inactive.raw", args.output / "damaged-recovery.raw")
    try:
        start, _ = gpt["partitions"](copied)["fvca-core"]
        with copied.open("r+b") as image:
            image.seek(start)
            previous = image.read(1)
            image.seek(start)
            image.write(bytes([previous[0] ^ 1]))
        altered = deepcopy(plan)
        altered["recovery"]["disk"]["path"] = str(copied)
        run("damaged-recovery", altered, failure=b"installed Hypervisor payload differs")
    finally:
        copied.unlink()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for item in ("client", "installer", "boot-evidence", "certificate", "output"):
        parser.add_argument(f"--{item}", type=lambda path: Path(path).absolute(), required=True)
    parser.add_argument("--epoch-policy-sha256", required=True)
    os.umask(0o077)
    qualify(parser.parse_args())
