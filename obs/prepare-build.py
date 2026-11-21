#!/usr/bin/env python3
"""Prepare native OBS image sources from a reviewed FVCA Git commit."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib
from xml.etree import ElementTree as ET


ROOT = Path(__file__).resolve().parent.parent
SOURCE = "https://github.com/thefutureisprivate/FVCA.git"
RECIPES = {
    "base": "obs/mkosi.conf",
    "hypervisor": "obs/hypervisor/mkosi.conf",
    "service-guest": "obs/service-guest/mkosi.conf",
}
GUEST_LOCKFILES = ("workload-admission/Cargo.lock", "release-client/Cargo.lock")
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"


def committed(revision, path):
    return subprocess.check_output(
        ["git", "-C", ROOT, "show", f"{revision}:{path}"], stderr=subprocess.PIPE,
    )


def pinned_archive(revision, component, file, limit):
    source = committed(revision, f"tools/{component}-source.env").decode("ascii")
    version = re.findall(rf"^{component}_version=([0-9.]+)$", source, re.MULTILINE)
    expected = re.findall(rf"^{component}_sha256=([0-9a-f]{{64}})$", source, re.MULTILINE)
    if len(version) != 1 or len(expected) != 1:
        raise ValueError(f"the reviewed commit must pin the {component} version and SHA-256 digest")
    with file.open("rb") as stream:
        archive = stream.read(limit + 1)
    if len(archive) > limit or hashlib.sha256(archive).hexdigest() != expected[0]:
        raise ValueError(f"{component} archive differs from the reviewed commit")
    return version[0], archive


def locked_crates(revision, lockfiles):
    crates = {}
    for lockfile in lockfiles:
        lock = tomllib.loads(committed(revision, lockfile).decode("utf-8"))
        for package in lock["package"]:
            if "source" not in package:
                continue
            name = f"{package['name']}-{package['version']}"
            digest = package["checksum"]
            if (package["source"] != REGISTRY or not re.fullmatch(r"[A-Za-z0-9_+.-]+", name)
                    or not re.fullmatch(r"[0-9a-f]{64}", digest)):
                raise ValueError(f"unsupported Rust dependency in {lockfile}")
            if crates.setdefault(name, digest) != digest:
                raise ValueError(f"Rust lockfiles disagree about {name}")
    return crates


def vendor_archive(revision, vendor, output, lockfiles, basename):
    crates = locked_crates(revision, lockfiles)
    for name, expected in crates.items():
        directory = vendor / name
        record = directory / ".cargo-checksum.json"
        if directory.is_symlink() or record.is_symlink():
            raise ValueError(f"unexpected symbolic link for vendored crate {name}")
        if json.loads(record.read_bytes())["package"] != expected:
            raise ValueError(f"vendored crate {name} differs from the reviewed lockfiles")

    name = f"{basename}.tar.zst"
    path = output / name
    subprocess.run([
        "tar", "--zstd", "--create", "--file", path, "--directory", vendor,
        "--sort=name", "--mtime=@0", "--owner=0", "--group=0", "--numeric-owner",
        "--format=gnu", "--null", "--files-from=-",
    ], input=b"".join(name.encode("ascii") + b"\0" for name in sorted(crates)), check=True)
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    (output / f"{basename}.sha256").write_text(f"{digest}  {name}\n", encoding="ascii")


def service_config(role, revision):
    services = ET.Element("services")
    scm = ET.SubElement(services, "service", name="obs_scm", mode="serveronly")
    for name, value in (
        ("scm", "git"), ("url", SOURCE), ("revision", revision),
        ("extract", RECIPES[role]), ("without-version", "1"),
    ):
        ET.SubElement(scm, "param", name=name).text = value
    ET.indent(services, space="  ")
    return ET.tostring(services, encoding="utf-8") + b"\n"


def prepare(args):
    if not re.fullmatch(r"[0-9a-f]{40}", args.revision):
        raise ValueError("use the complete Git commit ID")
    subprocess.run(
        ["git", "-C", ROOT, "cat-file", "-e", f"{args.revision}^{{commit}}"], check=True, capture_output=True,
    )
    committed(args.revision, RECIPES[args.role])
    if (args.role == "hypervisor") != (args.fwupd is not None):
        raise ValueError("the Hypervisor package requires the reviewed fwupd archive")
    if (args.role == "service-guest") != (args.vendor is not None):
        raise ValueError("the Service Guest package requires the locked Cargo vendor directory")
    if args.output.exists():
        raise ValueError("choose a new output directory")
    version, allocator = pinned_archive(args.revision, "allocator", args.allocator, 1024 * 1024)

    with tempfile.TemporaryDirectory(prefix=".fvca-obs-", dir=args.output.parent) as work:
        prepared = Path(work) / "package"
        prepared.mkdir(mode=0o700)
        (prepared / f"hardened_malloc-{version}.tar.gz").write_bytes(allocator)
        if args.role != "base":
            (prepared / f"fvca-{args.role}.target").touch(exist_ok=False)
        if args.fwupd is not None:
            version, firmware = pinned_archive(args.revision, "fwupd", args.fwupd, 64 * 1024 * 1024)
            (prepared / f"fwupd-{version}.tar.xz").write_bytes(firmware)
        vendor_archive(args.revision, args.uutils_vendor, prepared, ("uutils/Cargo.lock",), "fvca-uutils-vendor")
        if args.vendor is not None:
            vendor_archive(args.revision, args.vendor, prepared, GUEST_LOCKFILES, "fvca-rust-vendor")
        (prepared / "_service").write_bytes(service_config(args.role, args.revision))
        prepared.rename(args.output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("revision")
    parser.add_argument("allocator", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--role", choices=RECIPES, default="base")
    parser.add_argument("--fwupd", type=Path)
    parser.add_argument("--uutils-vendor", type=Path, required=True)
    parser.add_argument("--vendor", type=Path)
    args = parser.parse_args()
    try:
        prepare(args)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"OBS image source preparation failed: {error}\n")


if __name__ == "__main__":
    main()
