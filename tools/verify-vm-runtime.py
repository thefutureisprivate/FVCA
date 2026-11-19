#!/usr/bin/env python3
"""Verify a signed VM runtime candidate against its prepared FVCA core."""

import argparse
from pathlib import Path
import subprocess
import tempfile

from runtime_image import verify
import vm_runtime


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("certificate", type=Path)
    parser.add_argument("prepared_base", type=Path, help="directory prepared by verify-base.py --extract-root")
    args = parser.parse_args()
    try:
        with tempfile.TemporaryDirectory(prefix="fvca-verify-runtime-") as directory:
            root_hash = verify(args.image, args.certificate, args.prepared_base, Path(directory), vm_runtime)
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"FVCA runtime verification failed: {error}\n")
    print(f"Verified signed, additive VM runtime {root_hash}")


if __name__ == "__main__":
    main()
