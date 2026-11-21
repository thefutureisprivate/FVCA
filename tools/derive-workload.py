#!/usr/bin/env python3
"""Verify source admission and derive a workload root without signing keys."""

import argparse
from pathlib import Path
import subprocess
import tempfile

from workload_build import derive, publish, source_arguments


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source_arguments(parser)
    args = parser.parse_args()
    try:
        with tempfile.TemporaryDirectory(prefix=".fvca-workload-", dir=args.output.parent) as temporary:
            staged = Path(temporary) / "candidate"
            evidence, _, _ = derive(args, staged)
            publish(staged, args.output)
        print(f"Derived {evidence['service']} workload root {evidence['verity_root_hash']} {evidence['provenance']}")
    except (OSError, ValueError, TypeError, KeyError, IndexError, subprocess.SubprocessError) as error:
        parser.exit(1, f"FVCA workload derivation failed: {error}\n")


if __name__ == "__main__":
    main()
