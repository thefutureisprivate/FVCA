#!/usr/bin/python3
"""Authorize a shell-free, read-only assessment of one Host mirror member."""

import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

from core_image import extract_uki_section, inspect_uki
from guest_boot_bundle import public_key, sha256
from host_storage import AUTHENTICATED, selection, unique_fields
from runtime_boot import DISABLE_AUTOMATIC_EXTENSIONS, SECURE_KERNEL_OPTIONS, build_uki, run, verify_initrd


POLICY = "usr/lib/fvca/host-recovery"
COMMAND_LINE = " ".join((
    "rd.systemd.unit=fvca-host-recovery.target",
    "rd.systemd.mask=initrd-switch-root.target",
    "rd.systemd.mask=initrd-switch-root.service",
    "rd.systemd.mask=sysroot.mount",
    "rd.systemd.gpt_auto=no", "systemd.gpt_auto=no", "systemd.import_credentials=no",
    *DISABLE_AUTOMATIC_EXTENSIONS, *SECURE_KERNEL_OPTIONS,
    "selinux=1", "enforcing=1", "dm_verity.require_signatures=1",
    "proc_mem.force_override=never", "systemd.restrict_filesystem_access=exec",
    "nosmt=force", "intel_iommu=on", "intremap=on", "iommu.passthrough=0", "iommu.strict=1",
    "module_blacklist=igb,igc,virtio_net,kvm,kvm_intel,kvm_amd",
))
REQUIRED = (
    "usr/lib/fvca/host-storage-support-v4",
    "usr/lib/fvca/host-recovery-write-barrier-v1",
    "usr/lib/fvca/assess-host-recovery",
    "usr/lib/systemd/system/fvca-host-recovery.service",
    "usr/lib/systemd/system/fvca-host-recovery.target",
    "usr/bin/losetup", "usr/bin/cryptsetup", "usr/bin/sha256sum", "usr/bin/systemd-ask-password",
)
FORBIDDEN = (
    POLICY, f"{POLICY}.cmdline", "usr/lib/fvca/host-storage", "usr/lib/fvca/service-guest.composition",
    "usr/lib/fvca/hypervisor.composition", "usr/lib/fvca/direct-boot.cmdline",
)


def authorization(args, work):
    storage = selection(args.storage)
    if storage.protection != AUTHENTICATED:
        raise ValueError("recovery requires an authorized authenticated Host mirror")
    member = storage.members["ab".index(args.member)]
    backup = work / "header"
    if not args.header_backup.is_file() or not 0 < args.header_backup.stat().st_size <= 128 * 1024**2:
        raise ValueError("expected a bounded LUKS2 header backup")
    shutil.copyfile(args.header_backup, backup)
    if run("cryptsetup", "luksUUID", backup, capture_output=True).stdout != (member.volume + "\n").encode("ascii"):
        raise ValueError("recovery header has a different LUKS UUID")
    metadata = json.loads(run("cryptsetup", "luksDump", "--dump-json-metadata", backup, capture_output=True).stdout,
                          object_pairs_hook=unique_fields)
    slot = str(args.key_slot)
    if (slot not in metadata["keyslots"]
            or any(slot in token["keyslots"] for token in metadata["tokens"].values())):
        raise ValueError("recovery requires an independent LUKS2 keyslot")
    digest = sha256(backup)
    backup.unlink()
    now = int(time.time())
    return (f"FVCA-HOST-RECOVERY-1\npartition={member.partition}\nluks={member.volume}\n"
            f"filesystem={storage.filesystem}\nheader_sha256={digest}\nkey_slot={slot}\n"
            f"not_before={now}\nexpires={now + args.valid_seconds}\n")


def compose(args, work):
    if public_key(args.boot_certificate) in (public_key(args.host_certificate), public_key(args.staging_certificate)):
        raise ValueError("Host recovery requires a separate Secure Boot signing key")
    staged = work / "staged.efi"
    shutil.copyfile(args.staged_uki, staged)
    if sha256(staged) != args.staged_uki_sha256:
        raise ValueError("staged UKI differs from the approved SHA-256 digest")
    sections = inspect_uki(staged, args.staging_certificate)
    uname = sections[".uname"]["text"]
    args.initrd = work / "initrd.cpio.zst"
    for section, destination in (("linux", work / "linux"), ("osrel", work / "osrel"), ("initrd", args.initrd)):
        extract_uki_section(staged, section, destination)
    verify_initrd(args.initrd, uname, REQUIRED, FORBIDDEN, "native Hypervisor recovery-capable")
    staged.unlink()

    cmdline = COMMAND_LINE
    if args.serial_console:
        cmdline += " console=tty0 console=ttyS0,115200"
    archive = work / "recovery.cpio"
    (work / POLICY).parent.mkdir(parents=True)
    (work / POLICY).write_text(authorization(args, work), encoding="ascii")
    (work / f"{POLICY}.cmdline").write_text(cmdline + "\n", encoding="ascii")
    for entry in (POLICY, f"{POLICY}.cmdline"):
        (work / entry).chmod(0o644)
    with archive.open("wb") as output:
        run("cpio", "--quiet", "-o", "-0", "--format=newc", "--reproducible", "--owner=0:0",
            input=f"{POLICY}\0{POLICY}.cmdline\0".encode("ascii"), stdout=output, cwd=work)
    uki = build_uki(args, work, cmdline, uname, archive, ())
    if inspect_uki(uki, args.boot_certificate)[".cmdline"]["text"] != cmdline:
        raise ValueError("recovery UKI does not contain the authorized command line")
    args.output.hardlink_to(uki)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("staged-uki", "staging-certificate", "host-certificate", "boot-key", "boot-certificate",
                   "storage", "header-backup", "output"):
        parser.add_argument(f"--{option}", required=True, type=Path)
    parser.add_argument("--staged-uki-sha256", required=True)
    parser.add_argument("--member", required=True, choices=("a", "b"))
    parser.add_argument("--key-slot", required=True, type=int, choices=range(32))
    parser.add_argument("--valid-seconds", type=int, default=3600)
    parser.add_argument("--serial-console", action="store_true")
    args = parser.parse_args()
    if re.fullmatch(r"[0-9a-f]{64}", args.staged_uki_sha256) is None:
        parser.error("--staged-uki-sha256 must be a lowercase SHA-256 digest")
    if not 1 <= args.valid_seconds <= 86400:
        parser.error("--valid-seconds must be 1–86400")
    if args.output.exists():
        parser.error("output must not exist")
    try:
        with tempfile.TemporaryDirectory(prefix=".fvca-host-recovery-", dir=args.output.parent) as scratch:
            compose(args, Path(scratch).resolve())
    except (KeyError, OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Host recovery composition refused: {error}\n")


if __name__ == "__main__":
    main()
