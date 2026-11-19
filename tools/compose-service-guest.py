#!/usr/bin/env python3
"""Assemble a Secure Boot Service Guest with its authorized OCI runtime."""

import argparse
from pathlib import Path
import subprocess
import tempfile

import oci_runtime
from runtime_boot import (
    DISABLE_AUTOMATIC_EXTENSIONS, composition_archive, prepare_core, run, verify_initrd, write_disk,
)
from runtime_image import verify as verify_runtime


ROLE_BOOT_OPTIONS = (
    "module_blacklist=kvm,kvm_intel,kvm_amd",
    "rd.systemd.mask=systemd-sysext-initrd.service", "rd.systemd.mask=systemd-confext-initrd.service",
    *DISABLE_AUTOMATIC_EXTENSIONS,
)
ACTIVATION_FILES = (
    "usr/lib/fvca/activate-guest-data",
    "usr/lib/fvca/activate-oci-runtime",
    "usr/lib/fvca/guest-data",
    "usr/lib/systemd/system/fvca-activate-guest-data.service",
    "usr/lib/systemd/system/fvca-activate-oci-runtime.service",
    "usr/lib/systemd/system/initrd-parse-etc.service.d/21-fvca-oci-runtime.conf",
    "usr/lib/systemd/system/initrd-switch-root.service.d/20-fvca-guest-data.conf",
    "usr/lib/systemd/system/initrd-switch-root.service.d/21-fvca-oci-runtime.conf",
)
FORBIDDEN = tuple(f"usr/lib/fvca/{name}" for name in (
    "activate-runtime", "hypervisor.composition", "host-storage", "vm-runtime.p7s",
    "service-guest.composition", "oci-runtime.p7s",
))


def assemble(args, work):
    boot_key = run("openssl", "x509", "-in", args.boot_certificate, "-pubkey", "-noout", capture_output=True).stdout
    runtime_key = run("openssl", "x509", "-in", args.runtime_certificate, "-pubkey", "-noout", capture_output=True).stdout
    if boot_key == runtime_key:
        raise ValueError("Secure Boot and the OCI runtime require separate signing keys")

    prepared, core_hash, offset, cmdline, uname = prepare_core(args, work)
    verify_initrd(args.initrd, uname, ACTIVATION_FILES, FORBIDDEN, "Service Guest")
    runtime_work = work / "runtime"
    runtime_work.mkdir()
    runtime_hash = verify_runtime(args.runtime, args.runtime_certificate, prepared, runtime_work, oci_runtime)
    composition = composition_archive(
        work, args.boot_key, args.boot_certificate, core_hash, runtime_hash, "service-guest", oci_runtime.IMAGE_ID,
    )
    write_disk(args, work, offset, cmdline, uname, composition, ROLE_BOOT_OPTIONS)
    print(f"FVCA Service Guest development disk binds core {core_hash} to OCI runtime {runtime_hash}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("core", "runtime", "initrd", "boot-certificate", "boot-key", "runtime-certificate", "output"):
        parser.add_argument(f"--{name}", type=lambda value: Path(value).absolute(), required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output disk already exists")
    try:
        with tempfile.TemporaryDirectory(prefix=".fvca-service-guest-", dir=args.output.parent) as directory:
            assemble(args, Path(directory))
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"FVCA Service Guest composition failed: {error}\n")


if __name__ == "__main__":
    main()
