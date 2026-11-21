#!/usr/bin/env python3
"""Prepare native OBS base sources from a reviewed FVCA Git commit."""

import argparse
import hashlib
from pathlib import Path
import re
import subprocess
from xml.etree import ElementTree as ET


ROOT = Path(__file__).resolve().parent.parent
SOURCE = "https://github.com/thefutureisprivate/FVCA.git"


def committed(revision, path):
    return subprocess.check_output(
        ["git", "-C", ROOT, "show", f"{revision}:{path}"], stderr=subprocess.PIPE,
    )


def prepare(revision, allocator, output):
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("use the complete Git commit ID")
    subprocess.run(
        ["git", "-C", ROOT, "cat-file", "-e", f"{revision}^{{commit}}"], check=True, capture_output=True,
    )
    committed(revision, "obs/mkosi.conf")
    source = committed(revision, "tools/allocator-source.env").decode("ascii")
    version = re.findall(r"^allocator_version=([0-9]+)$", source, re.MULTILINE)
    expected = re.findall(r"^allocator_sha256=([0-9a-f]{64})$", source, re.MULTILINE)
    if len(version) != 1 or len(expected) != 1:
        raise ValueError("the reviewed commit must pin the allocator version and SHA-256 digest")
    with allocator.open("rb") as stream:
        archive = stream.read(1024 * 1024 + 1)
    if len(archive) > 1024 * 1024 or hashlib.sha256(archive).hexdigest() != expected[0]:
        raise ValueError("allocator archive differs from the reviewed commit")

    services = ET.Element("services")
    scm = ET.SubElement(services, "service", name="obs_scm", mode="serveronly")
    for name, value in (
        ("scm", "git"), ("url", SOURCE), ("revision", revision),
        ("extract", "obs/mkosi.conf"), ("without-version", "1"),
    ):
        ET.SubElement(scm, "param", name=name).text = value
    ET.indent(services, space="  ")
    output.mkdir(mode=0o700)
    (output / "_service").write_bytes(ET.tostring(services, encoding="utf-8") + b"\n")
    (output / f"hardened_malloc-{version[0]}.tar.gz").write_bytes(archive)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("revision")
    parser.add_argument("allocator", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        prepare(args.revision, args.allocator, args.output)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"OBS base source preparation failed: {error}\n")


if __name__ == "__main__":
    main()
