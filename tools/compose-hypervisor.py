#!/usr/bin/env python3
"""Assemble a Secure Boot Hypervisor development disk without rewriting its core."""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

from image_verity import VERITY_PARTITIONS, read_layout
from vm_runtime_image import verify as verify_vm_runtime


TOOLS = Path(__file__).resolve().parent
PARTITIONS = {"esp": "c12a7328-f81f-11d2-ba4b-00a0c93ec93b", **VERITY_PARTITIONS}
BOOT_EFI = "::/EFI/BOOT/BOOTX64.EFI"
PCR_POLICY_REF = "fvca-host-storage"
ROLE_BOOT_OPTIONS = (
    "kvm_intel.nested=0",
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
    "usr/lib/systemd/system/initrd-switch-root.service.d/20-fvca-runtime.conf",
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
    for name in ("hypervisor.composition", "vm-runtime.p7s", "host-storage"):
        if f"usr/lib/fvca/{name}" in paths:
            raise ValueError("expected an unconfigured Hypervisor initramfs")


def storage_selection(path):
    content = path.read_bytes()
    uuid = r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"
    match = re.fullmatch(
        rf"FVCA-HOST-STORAGE-2\nunlock=(development-passphrase|tpm2-pin)\n"
        rf"member_a=({uuid})\nmember_b=({uuid})\n"
        rf"raid=(?:[0-9a-f]{{8}}:){{3}}[0-9a-f]{{8}}\n"
        rf"luks={uuid}\nfilesystem=btrfs\nfilesystem_uuid={uuid}\n"
        rf"(token=(?:[0-9]|[12][0-9]|3[01]),[0-9a-f]{{64}}\n)?",
        content.decode("ascii"),
    )
    if match is None or match[2] == match[3] or (match[1] == "tpm2-pin") != (match[4] is not None):
        raise ValueError("invalid Hypervisor storage selection")
    return content


def unique_fields(pairs):
    fields = dict(pairs)
    if len(fields) != len(pairs):
        raise ValueError("duplicate fields in the LUKS2 TPM token")
    return fields


def verify_tpm_token(path, storage, pcr_public):
    raw = path.read_bytes()
    expected = storage.splitlines()[-1].split(b",", 1)[1].decode("ascii")
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("exported LUKS2 token does not match the signed storage selection")
    token = json.loads(raw, object_pairs_hook=unique_fields)
    if (
        token["type"] != "systemd-tpm2"
        or token["tpm2-pin"] is not True
        or token["tpm2-pcrs"] != [7, 12, 13]
        or token["tpm2-pcr-bank"] != "sha256"
        or token["tpm2_pubkey_pcrs"] != [11]
        or token["tpm2_pubkey_ref"] != PCR_POLICY_REF
    ):
        raise ValueError("LUKS2 token does not require a PIN and the approved PCR policy")
    for parameter in ("memcost", "iterations", "lanes"):
        value = token[f"tpm2_argon2id_{parameter}"]
        if type(value) is not int or value < 1:
            raise ValueError("the LUKS2 token must harden the PIN with Argon2id")
    token_public = base64.b64decode(token["tpm2_pubkey"], validate=True)
    if run("openssl", "pkey", "-pubin", "-outform", "DER",
           input=token_public, capture_output=True).stdout != pcr_public:
        raise ValueError("the enrolled PCR authority does not match the PCR signing key")


def composition_archive(work, boot_key, boot_certificate, core_hash, runtime_hash, storage):
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
    paths = [composition, signature]
    if storage is not None:
        selection = files / "host-storage"
        selection.write_bytes(storage)
        paths.append(selection)
    payload = b"".join(bytes(path.relative_to(work)) + b"\0" for path in paths)
    archive = work / "composition.cpio"
    for path in paths:
        path.chmod(0o644)
    with archive.open("wb") as output:
        run("cpio", "--quiet", "-o", "-0", "--format=newc", "--reproducible", "--owner=0:0",
            input=payload, stdout=output, cwd=work)
    return archive


def assemble(args, work):
    storage = storage_selection(args.storage) if args.storage is not None else None
    tpm = storage is not None and storage.splitlines()[1] == b"unlock=tpm2-pin"
    if tpm != (args.pcr_key is not None) or tpm != (args.tpm_token is not None):
        raise ValueError("TPM storage requires a separate PCR signing key and an exported LUKS2 token")
    pcr_options = []
    if tpm:
        boot_public = run("openssl", "pkey", "-in", args.boot_key, "-pubout", "-outform", "DER",
                          capture_output=True).stdout
        pcr_public = run("openssl", "pkey", "-in", args.pcr_key, "-pubout", "-outform", "DER",
                         capture_output=True).stdout
        if pcr_public == boot_public:
            raise ValueError("PCR policy and Secure Boot must use different signing keys")
        verify_tpm_token(args.tpm_token, storage, pcr_public)
        pcr_options = [
            f"--pcr-private-key={args.pcr_key}",
            "--pcr-banks=sha256", "--phases=enter-initrd", f"--policyref={PCR_POLICY_REF}",
        ]
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
    composition = composition_archive(work, args.boot_key, args.boot_certificate, core_hash, runtime_hash, storage)

    uki = work / "hypervisor.efi"
    run("ukify", "build", "--config=/dev/null", f"--linux={work / 'linux'}",
        f"--os-release=@{work / 'osrel'}", f"--uname={uname}",
        f"--cmdline={cmdline} {' '.join(ROLE_BOOT_OPTIONS)}",
        f"--initrd={args.initrd}", f"--initrd={composition}",
        f"--secureboot-private-key={args.boot_key}", f"--secureboot-certificate={args.boot_certificate}",
        *pcr_options, "--no-sign-kernel", f"--output={uki}")

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
    parser.add_argument("--storage", type=Path, help="host storage selection to embed in the signed UKI")
    parser.add_argument("--pcr-key", type=Path, help="separate RSA private key for the initrd PCR policy")
    parser.add_argument("--tpm-token", type=Path, help="exported LUKS2 token to check before signing")
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
