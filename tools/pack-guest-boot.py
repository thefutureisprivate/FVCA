#!/usr/bin/env python3
"""Package a verified Guest boot bundle as a read-only dm-verity disk."""

import argparse
from pathlib import Path
import subprocess
import tempfile

import guest_boot_bundle
from image_verity import VERITY_PARTITIONS, read_layout, verify_verity
from runtime_boot import run


def pack(args, work):
    bundle = work / "bundle"
    bundle.mkdir(mode=0o755)
    for name in guest_boot_bundle.BUNDLE_FILES:
        source = args.bundle / name
        if source.is_symlink() or not source.is_file():
            raise ValueError(f"invalid Guest boot bundle input {name}")
        destination = bundle / name
        run("cp", "--reflink=auto", "--sparse=always", "--", source, destination)
        destination.chmod(0o644)
    if guest_boot_bundle.public_key(args.release_certificate) == guest_boot_bundle.public_key(args.verity_certificate):
        raise ValueError("the Guest release signer and Host verity signer require separate keys")
    guest_boot_bundle.verify(bundle, args.release_certificate)

    contexts = work / "file_contexts"
    contexts.write_text("/.* system_u:object_r:virt_content_t:s0\n", encoding="ascii")
    filesystem = work / "guest-boot.erofs"
    run("mkfs.erofs", "--all-root", "-T0", "-zlz4hc", f"--file-contexts={contexts}", filesystem, bundle)
    definitions = work / "repart.d"
    definitions.mkdir()
    for index, (kind, layout) in enumerate((
        ("root", f"Verity=data\nCopyBlocks={filesystem}\n"),
        ("root-verity", "Verity=hash\nSizeMinBytes=16M\n"),
        ("root-verity-sig", "Verity=signature\n"),
    )):
        (definitions / f"{index:02}.conf").write_text(
            f"[Partition]\nType={kind}\nReadOnly=yes\nVerityMatchKey=guest-boot\n{layout}", encoding="ascii"
        )
    image = work / "guest-boot.raw"
    run("systemd-repart", "--empty=create", "--size=auto", "--dry-run=no", f"--definitions={definitions}",
        f"--private-key={args.verity_key}", f"--certificate={args.verity_certificate}", image)
    sector_size, partitions = read_layout(image, VERITY_PARTITIONS)
    root_hash = verify_verity(image, sector_size, partitions, args.verity_certificate, work)
    args.output.hardlink_to(image)
    print(f"FVCA verified Guest boot bundle root {root_hash}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("bundle", "release-certificate", "verity-key", "verity-certificate", "output"):
        parser.add_argument(f"--{name}", required=True, type=lambda value: Path(value).absolute())
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists")
    try:
        with tempfile.TemporaryDirectory(prefix=".fvca-guest-boot-", dir=args.output.parent) as directory:
            pack(args, Path(directory))
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"FVCA Guest boot packing failed: {error}\n")


if __name__ == "__main__":
    main()
