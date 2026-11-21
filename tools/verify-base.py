#!/usr/bin/env python3
"""Verify the boot and root artifacts in an FVCA development disk off-node."""

import argparse
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from core_image import extract_uki_section, verify


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
    extract_uki_section(work / "boot.efi", "initrd", initrd)
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
