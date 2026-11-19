#!/usr/bin/env python3
"""Reject shared package version drift in the mkosi VM runtime transaction."""

import json
import os
from pathlib import Path
import sys


def rpm_versions(path):
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if not manifest["packages"]:
        raise ValueError(f"no packages in {path}")
    return {(p["name"], p["architecture"]): p["version"] for p in manifest["packages"]}


def main():
    output = Path(os.environ["OUTPUTDIR"])
    prepared = Path(os.environ["SRCDIR"]) / "build/vm-runtime-base"
    core = rpm_versions(prepared / "packages.json")
    runtime = rpm_versions(output / "vm-runtime.manifest")
    mismatches = sorted(name for name in core.keys() & runtime.keys() if core[name] != runtime[name])
    if mismatches:
        sys.exit(f"FVCA runtime package version drift: {mismatches}")
    print(f"Matching versions for {len(core.keys() & runtime.keys())} shared Fedora packages")


if __name__ == "__main__":
    main()
