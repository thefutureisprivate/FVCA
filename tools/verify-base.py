#!/usr/bin/env python3
"""Verify the boot and root artifacts in an FVCA development disk off-node."""

import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

from image_verity import VERITY_PARTITIONS, read_layout, verify_verity
from runtime_boot import BASE_ROOT_OPTIONS, DIRECT_ROOT_OPTIONS


PARTITIONS = {
    "esp": "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
    **VERITY_PARTITIONS,
}
BOOT_OPTIONS = {
    "dm_verity.require_signatures": "1",
    "enforcing": "1",
    "proc_mem.force_override": "never",
    "systemd.restrict_filesystem_access": "exec",
    "systemd.verity_root_options": BASE_ROOT_OPTIONS,
}


def verify(image, boot_certificate, verity_certificate, work, *, direct_boot=False):
    sector_size, partitions = read_layout(image, PARTITIONS)
    uki = work / "boot.efi"
    esp_offset = partitions["esp"]["start"] * sector_size
    subprocess.run(["mcopy", "-i", f"{image}@@{esp_offset}", "::/EFI/BOOT/BOOTX64.EFI", uki], check=True)
    subprocess.run(["sbverify", "--cert", boot_certificate, uki], check=True)
    sections = json.loads(subprocess.check_output(["ukify", "--json=short", "inspect", uki]))
    if sections.get("_profiles"):
        raise ValueError("unexpected UKI profiles")

    arguments = [arg.partition("=") for arg in sections[".cmdline"]["text"].split()]
    options = BOOT_OPTIONS
    if direct_boot:
        options = {**BOOT_OPTIONS, "systemd.verity_root_options": DIRECT_ROOT_OPTIONS,
                   "module.sig_enforce": "1", "lockdown": "integrity"}
    for option, expected in options.items():
        values = [value for name, _, value in arguments if name == option]
        if values != [expected]:
            raise ValueError(f"the signed UKI must specify exactly one {option}={expected}")

    hashes = [value for name, _, value in arguments if name == "roothash"]
    if len(hashes) != 1 or re.fullmatch(r"[0-9a-f]{64}", hashes[0]) is None:
        raise ValueError("the signed UKI must specify one SHA-256 root hash")
    root_hash = verify_verity(image, sector_size, partitions, verity_certificate, work, hashes[0])
    print(f"Verified UKI execution policy, DDI signature and dm-verity data for {root_hash}")
    return root_hash


def export_tree(root, root_hash, destination, manifest):
    package_manifest = manifest.read_bytes()
    destination.mkdir()
    # The extracted copy is a build input. Labels are assigned when formatting the runtime image.
    subprocess.run(["fsck.erofs", f"--extract={destination / 'root'}", "--preserve-perms", root], check=True)
    (destination / "roothash").write_text(f"{root_hash}\n", encoding="ascii")
    shutil.copyfile(root.parent / "root.p7s", destination / "root.p7s")
    (destination / "packages.json").write_bytes(package_manifest)


def export_initrd(work, destination):
    initrd = work / "initrd"
    subprocess.run(
        ["ukify", f"--section=.initrd:binary@{initrd}", "inspect", work / "boot.efi"],
        check=True, stdout=subprocess.DEVNULL,
    )
    if not initrd.stat().st_size:
        raise ValueError("the verified UKI has an empty initramfs")
    with initrd.open("rb") as source, destination.open("xb") as output:
        shutil.copyfileobj(source, output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=lambda value: Path(value).resolve())
    parser.add_argument("boot_certificate", type=Path)
    parser.add_argument("--verity-certificate", type=Path, help="defaults to the boot certificate")
    parser.add_argument("--extract-root", type=Path, help="prepare a new runtime build input directory")
    parser.add_argument("--extract-initrd", type=Path, help="write the verified UKI's initramfs to a new file")
    parser.add_argument("--direct-boot", action="store_true", help="verify the signed Service Guest direct-boot options")
    args = parser.parse_args()
    required_tools = ["mcopy", "openssl", "sbverify", "sfdisk", "ukify", "veritysetup"]
    if args.extract_root:
        required_tools.append("fsck.erofs")
    for tool in required_tools:
        if shutil.which(tool) is None:
            parser.exit(1, f"Required tool is missing: {tool}\n")

    try:
        with tempfile.TemporaryDirectory(prefix="fvca-verify-") as directory:
            work = Path(directory)
            root_hash = verify(args.image, args.boot_certificate, args.verity_certificate or args.boot_certificate,
                               work, direct_boot=args.direct_boot)
            if args.extract_root:
                export_tree(work / "root", root_hash, args.extract_root, args.image.with_suffix(".manifest"))
            if args.extract_initrd:
                export_initrd(work, args.extract_initrd)
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print(f"FVCA image verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
