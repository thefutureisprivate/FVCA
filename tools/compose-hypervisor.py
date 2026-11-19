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

from runtime_boot import (
    DISABLE_AUTOMATIC_EXTENSIONS, WORKLOAD_TRUST_FILES, composition_archive, prepare_core, run, verify_initrd, write_disk,
)
from runtime_image import verify as verify_runtime
import vm_runtime


PCR_POLICY_REF = "fvca-host-storage"
ROLE_BOOT_OPTIONS = ("kvm_intel.nested=0", *DISABLE_AUTOMATIC_EXTENSIONS)
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
    prepared, core_hash, offset, cmdline, uname = prepare_core(args, work)
    runtime_work = work / "runtime"
    runtime_work.mkdir()
    runtime_hash = verify_runtime(args.runtime, args.runtime_certificate, prepared, runtime_work, vm_runtime)
    forbidden = tuple(f"usr/lib/fvca/{name}" for name in (
        "hypervisor.composition", "vm-runtime.p7s", "host-storage", *WORKLOAD_TRUST_FILES,
    ))
    verify_initrd(args.initrd, uname, ACTIVATION_FILES, forbidden, "Hypervisor")
    composition = composition_archive(
        work, args.boot_key, args.boot_certificate, core_hash, runtime_hash, "hypervisor", "vm-runtime",
        extra=(("host-storage", storage),) if storage is not None else (),
    )
    write_disk(args, work, offset, cmdline, uname, composition, ROLE_BOOT_OPTIONS, uki_options=pcr_options)
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
