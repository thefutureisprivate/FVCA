#!/usr/bin/env python3
"""Record the files in a verified FVCA role core, initramfs and runtime."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

import oci_runtime
import vm_runtime
from file_inventory import initramfs_inventory, tree_inventory
from guest_boot_bundle import public_key, sha256
from runtime_boot import TOOLS, run
from runtime_image import verify as verify_runtime


ROLES = {
    "hypervisor": (vm_runtime, "/usr/lib/fvca/activate-runtime"),
    "service-guest": (oci_runtime, "/usr/lib/fvca/activate-oci-runtime"),
}


def snapshot(image, destination):
    run("cp", "--reflink=auto", "--sparse=always", "--", image, destination)
    shutil.copyfile(image.with_suffix(".manifest"), destination.with_suffix(".manifest"))


def image_record(image, root_hash, certificate, tree):
    der = run("openssl", "x509", "-in", certificate, "-outform", "DER", capture_output=True).stdout
    return {
        "image_sha256": sha256(image),
        "package_manifest_sha256": sha256(image.with_suffix(".manifest")),
        "signer_certificate_sha256": hashlib.sha256(der).hexdigest(),
        "verity_root": root_hash,
        "files": tree_inventory(tree),
    }


def inventory(args, work):
    if public_key(args.core_certificate) == public_key(args.runtime_certificate):
        raise ValueError("the core and runtime require distinct signing keys")
    policy, activation = ROLES[args.role]
    core = work / "core.raw"
    runtime = work / "runtime.raw"
    snapshot(args.core, core)
    snapshot(args.runtime, runtime)
    prepared = work / "core"
    initrd = work / "initrd.cpio.zst"
    run("python3", TOOLS / "verify-base.py", core, args.core_certificate,
        "--extract-root", prepared, "--extract-initrd", initrd)
    startup = initramfs_inventory(initrd)
    initrd_files = {entry["path"] for entry in startup if entry["type"] == "file"}
    for path in (activation, "/usr/lib/systemd/systemd"):
        if path not in initrd_files:
            raise ValueError(f"the authenticated {args.role} initramfs lacks {path}")
    runtime_work = work / "runtime"
    runtime_work.mkdir()
    runtime_hash = verify_runtime(runtime, args.runtime_certificate, prepared, runtime_work, policy)
    core_hash = (prepared / "roothash").read_text(encoding="ascii").strip()
    report = {
        "schema": "fvca-role-file-inventory-v1", "role": args.role, "runtime_id": policy.IMAGE_ID,
        "core": image_record(core, core_hash, args.core_certificate, prepared / "root"),
        "runtime": image_record(runtime, runtime_hash, args.runtime_certificate, runtime_work / "tree"),
        "core_initramfs": {"sha256": sha256(initrd), "files": startup},
    }
    result = work / "inventory.json"
    with result.open("x", encoding="ascii") as output:
        json.dump(report, output, sort_keys=True, separators=(",", ":"))
        output.write("\n")
    args.output.hardlink_to(result)
    print(f"Inventoried {args.role}: {len(report['core']['files'])} core, "
          f"{len(report['runtime']['files'])} runtime and {len(startup)} initramfs entries")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=ROLES)
    for name in ("core", "core-certificate", "runtime", "runtime-certificate", "output"):
        parser.add_argument(f"--{name}", type=lambda value: Path(value).absolute(), required=True)
    args = parser.parse_args()
    try:
        if args.output.exists() or args.output.is_symlink():
            raise ValueError("use a new inventory file")
        with tempfile.TemporaryDirectory(prefix=".fvca-role-inventory-", dir=args.output.parent) as work:
            inventory(args, Path(work))
    except (OSError, KeyError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"FVCA file inventory failed: {error}\n")


if __name__ == "__main__":
    main()
