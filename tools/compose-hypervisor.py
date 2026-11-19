#!/usr/bin/env python3
"""Assemble a Secure Boot Hypervisor development disk without rewriting its core."""

import argparse
import json
from pathlib import Path
import subprocess
import tempfile

from image_verity import VERITY_PARTITIONS, read_layout
from vm_runtime_image import verify as verify_vm_runtime


TOOLS = Path(__file__).resolve().parent
PARTITIONS = {"esp": "c12a7328-f81f-11d2-ba4b-00a0c93ec93b", **VERITY_PARTITIONS}
BOOT_EFI = "::/EFI/BOOT/BOOTX64.EFI"
DISCOVERY_DISABLED = (
    "rd.systemd.sysext=no", "rd.systemd.confext=no", "systemd.sysext=no", "systemd.confext=no",
    "rd.systemd.mask=systemd-sysext.socket", "rd.systemd.mask=systemd-confext.socket",
    "systemd.mask=systemd-sysext.socket", "systemd.mask=systemd-confext.socket",
)
ACTIVATION_FILES = (
    "etc/systemd/system/systemd-confext-initrd.service",
    "etc/systemd/system/systemd-confext-sysroot.service",
    "etc/systemd/system/systemd-sysext-initrd.service",
    "etc/systemd/system/systemd-sysext-sysroot.service",
    "usr/lib/fvca/activate-runtime",
    "usr/lib/systemd/system/fvca-activate-runtime.service",
    "usr/lib/systemd/system/initrd-parse-etc.service.d/20-fvca-runtime.conf",
    "usr/lib/systemd/system/initrd-switch-root.target.d/20-fvca-runtime.conf",
)


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def verify_initrd(initrd, uname):
    with subprocess.Popen(["zstd", "-dc", initrd], stdout=subprocess.PIPE) as decompressor:
        with decompressor.stdout:
            entries = run("cpio", "--quiet", "-it", stdin=decompressor.stdout, capture_output=True, text=True)
        if decompressor.wait():
            raise ValueError("could not decompress the Hypervisor initramfs")
    paths = entries.stdout.splitlines()
    if any(paths.count(path) != 1 for path in ACTIVATION_FILES):
        raise ValueError("expected the Hypervisor initramfs with its activation units")
    if f"usr/lib/modules/{uname}/modules.dep" not in paths:
        raise ValueError("the Hypervisor initramfs does not match the core kernel")
    for name in ("hypervisor.composition", "vm-runtime.p7s"):
        if f"usr/lib/fvca/{name}" in paths:
            raise ValueError("expected an unconfigured Hypervisor initramfs")


def authorize_runtime(work, boot_key, boot_certificate, core_hash, runtime_hash):
    root_hash_file = work / "runtime.roothash"
    root_hash_file.write_text(runtime_hash, encoding="ascii")
    files = work / "usr/lib/fvca"
    files.mkdir(parents=True)
    composition = files / "hypervisor.composition"
    composition.write_text(
        f"FVCA-DEVELOPMENT-1\nrole=hypervisor\nruntime=vm-runtime\n"
        f"core={core_hash}\nruntime_root={runtime_hash}\n",
        encoding="ascii",
    )
    signature = files / "vm-runtime.p7s"
    # The runtime artifact passed independent signer verification. This signature
    # authorizes its root on the disposable kernel's existing verity keyring.
    run("openssl", "cms", "-sign", "-binary", "-nocerts", "-noattr", "-outform", "DER",
        "-in", root_hash_file, "-signer", boot_certificate, "-inkey", boot_key, "-out", signature)
    payload = b"usr/lib/fvca/hypervisor.composition\0usr/lib/fvca/vm-runtime.p7s\0"
    archive = work / "composition.cpio"
    for path in (composition, signature):
        path.chmod(0o644)
    with archive.open("wb") as output:
        run("cpio", "--quiet", "-o", "-0", "--format=newc", "--reproducible", "--owner=0:0",
            input=payload, stdout=output, cwd=work)
    return archive


def assemble(args, work):
    prepared = work / "core"
    run("python3", TOOLS / "verify-base.py", args.core, args.boot_certificate, "--extract-root", prepared)
    core_hash = (prepared / "roothash").read_text(encoding="ascii").strip()
    runtime_work = work / "runtime"
    runtime_work.mkdir()
    runtime_hash = verify_vm_runtime(args.runtime, args.runtime_certificate, prepared, runtime_work)

    sector_size, partitions = read_layout(args.core, PARTITIONS)
    offset = partitions["esp"]["start"] * sector_size
    base_uki = work / "base.efi"
    run("mcopy", "-i", f"{args.core}@@{offset}", BOOT_EFI, base_uki)
    run("sbverify", "--cert", args.boot_certificate, base_uki)
    metadata = json.loads(run("ukify", "--json=short", "inspect", base_uki, capture_output=True).stdout)
    cmdline = metadata[".cmdline"]["text"]
    if [part for part in cmdline.split() if part.startswith("roothash=")] != [f"roothash={core_hash}"]:
        raise ValueError("the signed core UKI does not match the prepared root")
    for section in ("linux", "osrel"):
        run("ukify", f"--section=.{section}:binary@{work / section}", "inspect", base_uki,
            stdout=subprocess.DEVNULL)
    uname = metadata[".uname"]["text"]
    verify_initrd(args.initrd, uname)
    composition = authorize_runtime(work, args.boot_key, args.boot_certificate, core_hash, runtime_hash)

    uki = work / "hypervisor.efi"
    run("ukify", "build", "--config=/dev/null", f"--linux={work / 'linux'}",
        f"--os-release=@{work / 'osrel'}", f"--uname={uname}",
        f"--cmdline={cmdline} {' '.join(DISCOVERY_DISABLED)}",
        f"--initrd={args.initrd}", f"--initrd={composition}",
        f"--secureboot-private-key={args.boot_key}", f"--secureboot-certificate={args.boot_certificate}",
        "--no-sign-kernel", f"--output={uki}")

    disk = work / "hypervisor.raw"
    run("cp", "--reflink=auto", "--sparse=always", "--", args.core, disk)
    run("mdel", "-i", f"{disk}@@{offset}", BOOT_EFI)
    run("mcopy", "-i", f"{disk}@@{offset}", uki, BOOT_EFI)
    run("python3", TOOLS / "verify-base.py", disk, args.boot_certificate)
    # Hard-link into the output location so a concurrent writer cannot be overwritten.
    args.output.hardlink_to(disk)
    print(f"FVCA Hypervisor development disk binds core {core_hash} to VM runtime {runtime_hash}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("core", "runtime", "initrd", "boot-certificate", "boot-key", "runtime-certificate", "output"):
        parser.add_argument(f"--{name}", type=lambda value: Path(value).absolute(), required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output disk already exists")
    try:
        with tempfile.TemporaryDirectory(prefix=".fvca-hypervisor-", dir=args.output.parent) as directory:
            assemble(args, Path(directory))
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"FVCA Hypervisor composition failed: {error}\n")


if __name__ == "__main__":
    main()
