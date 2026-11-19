#!/usr/bin/env python3
"""Finalize the selected FVCA runtime in the mkosi build sandbox."""

import importlib
import os
from pathlib import Path
import sys


def main():
    source = Path(os.environ["SRCDIR"])
    sys.path.insert(0, str(source / "tools"))
    modules = {"vm-runtime": "vm_runtime", "oci-runtime": "oci_runtime"}
    runtime = importlib.import_module(modules[os.environ["FVCA_RUNTIME"]])
    runtime_tree = importlib.import_module("runtime_tree")
    prepared = source / "build" / runtime.BASE_INPUT
    try:
        runtime_tree.pack(
            Path(os.environ["BUILDROOT"]), prepared / "root",
            (prepared / "roothash").read_text(encoding="ascii").strip(),
            binding=runtime.BASE_BINDING, inspect=runtime.inspect_tree,
        )
    except (OSError, ValueError, RuntimeError) as error:
        sys.exit(f"FVCA {runtime.IMAGE_ID} payload rejected: {error}")
    print(f"FVCA {runtime.IMAGE_ID} payload is additive and shell-free")


if __name__ == "__main__":
    main()
