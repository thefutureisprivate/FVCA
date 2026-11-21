#!/usr/bin/python3
"""Authorize shell-free assessment, header restoration, or mirror replacement."""

import argparse
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

from core_image import extract_uki_section, inspect_uki
from guest_boot_bundle import public_key, sha256
from host_storage import AUTHENTICATED, SUPPORT, copy_header, independent_recovery_slot, selection, tpm_enrollment
from runtime_boot import DISABLE_AUTOMATIC_EXTENSIONS, SECURE_KERNEL_OPTIONS, build_uki, run, verify_initrd


POLICY = "usr/lib/fvca/host-recovery"
REPLACEMENT_UNIT = "usr/lib/systemd/system/fvca-host-recovery.service.d/90-replacement.conf"
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
    SUPPORT,
    "usr/lib/fvca/host-recovery-write-barrier-v1",
    "usr/lib/fvca/host-recovery-header-media-v1",
    "usr/lib/fvca/host-mirror-replacement-v1",
    "usr/lib/fvca/assess-host-recovery",
    "usr/lib/systemd/system/fvca-host-recovery.service",
    "usr/lib/systemd/system/fvca-host-recovery.target",
    "usr/bin/losetup", "usr/bin/cryptsetup", "usr/bin/sha256sum", "usr/bin/systemd-ask-password",
)
FORBIDDEN = (
    POLICY, f"{POLICY}.cmdline", "usr/lib/fvca/host-storage", "usr/lib/fvca/service-guest.composition",
    "usr/lib/fvca/hypervisor.composition", "usr/lib/fvca/direct-boot.cmdline", REPLACEMENT_UNIT,
)


def inspect_header(path, member, unlock, slot, work):
    backup = work / "header"
    slot = str(slot)
    header = copy_header(path, backup, member)
    public = None
    if member.token_index is not None:
        public, enrolled_slot = tpm_enrollment(header, member, unlock)
        if enrolled_slot != slot:
            raise ValueError("selected recovery slot differs from the independent enrollment")
    elif not independent_recovery_slot(header.metadata, slot):
        raise ValueError("recovery requires an independent LUKS2 keyslot")
    backup.unlink()
    return header, public


def replacement_selection(args, storage, index, survivor_key, work):
    if args.replacement_storage is None:
        return "none"
    planned = selection(args.replacement_storage)
    failed = storage.members[1 - index]
    new = planned.members[1 - index]
    if (planned.protection != AUTHENTICATED or planned.unlock != storage.unlock
            or planned.filesystem != storage.filesystem or planned.members[index] != storage.members[index]
            or new.partition in {member.partition for member in storage.members}
            or new.volume in {member.volume for member in storage.members}):
        raise ValueError("replacement storage must preserve the survivor and authorize one new authenticated member")
    header, public = inspect_header(args.replacement_header_backup, new, planned.unlock, args.replacement_key_slot, work)
    if public != survivor_key:
        raise ValueError("replacement and survivor must use the same enrolled PCR policy key")
    return ",".join((failed.partition, str(args.missing_devid), args.missing_member_uuid,
                     new.partition, new.volume, header.digest, str(args.replacement_key_slot)))


def authorization(args, work):
    storage = selection(args.storage)
    if storage.protection != AUTHENTICATED:
        raise ValueError("recovery requires an authorized authenticated Host mirror")
    index = "ab".index(args.member)
    member = storage.members[index]
    header, public = inspect_header(args.header_backup, member, storage.unlock, args.key_slot, work)
    media = "none"
    if args.header_media_partuuid is not None:
        if args.header_media_partuuid in {item.partition for item in storage.members}:
            raise ValueError("the backup header requires a separate media partition")
        if header.size != header.payload_offset:
            raise ValueError("the backup must cover exactly the aligned LUKS2 metadata and keyslot extent")
        media = f"{args.header_media_partuuid},{header.size}"
    replacement = replacement_selection(args, storage, index, public, work)
    now = int(time.time())
    return (f"FVCA-HOST-RECOVERY-3\npartition={member.partition}\nluks={member.volume}\n"
            f"filesystem={storage.filesystem}\nheader_sha256={header.digest}\nkey_slot={args.key_slot}\n"
            f"header_media={media}\nrestore_from={args.restore_from_sha256 or 'none'}\n"
            f"replacement={replacement}\n"
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
    entries = [POLICY, f"{POLICY}.cmdline"]
    if args.replacement_storage is not None:
        unit_directory = (work / REPLACEMENT_UNIT).parent
        unit_directory.mkdir(parents=True)
        (work / REPLACEMENT_UNIT).write_text("[Service]\nTimeoutStartSec=24h\n", encoding="ascii")
        entries.extend([unit_directory.relative_to(work).as_posix(), REPLACEMENT_UNIT])
    for entry in entries:
        path = work / entry
        path.chmod(0o755 if path.is_dir() else 0o644)
    with archive.open("wb") as output:
        run("cpio", "--quiet", "-o", "-0", "--format=newc", "--reproducible", "--owner=0:0",
            input=b"".join(entry.encode("ascii") + b"\0" for entry in entries), stdout=output, cwd=work)
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
    parser.add_argument("--header-media-partuuid", help="read the backup from this dedicated GPT partition")
    parser.add_argument("--restore-from-sha256", help="authorize replacing exactly this current on-disk header digest")
    parser.add_argument("--replacement-storage", type=Path)
    parser.add_argument("--replacement-header-backup", type=Path)
    parser.add_argument("--replacement-key-slot", type=int, choices=range(32))
    parser.add_argument("--missing-devid", type=int)
    parser.add_argument("--missing-member-uuid")
    parser.add_argument("--valid-seconds", type=int, default=3600)
    parser.add_argument("--serial-console", action="store_true")
    args = parser.parse_args()
    if re.fullmatch(r"[0-9a-f]{64}", args.staged_uki_sha256) is None:
        parser.error("--staged-uki-sha256 must be a lowercase SHA-256 digest")
    if args.header_media_partuuid is not None and (
        re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", args.header_media_partuuid) is None
        or args.header_media_partuuid == "00000000-0000-0000-0000-000000000000"
    ):
        parser.error("--header-media-partuuid must be a nonzero canonical GPT partition UUID")
    if args.restore_from_sha256 is not None and (
        args.header_media_partuuid is None or re.fullmatch(r"[0-9a-f]{64}", args.restore_from_sha256) is None
    ):
        parser.error("--restore-from-sha256 requires a lowercase SHA-256 digest and --header-media-partuuid")
    replacement = (args.replacement_storage, args.replacement_header_backup, args.replacement_key_slot,
                   args.missing_devid, args.missing_member_uuid)
    if any(value is not None for value in replacement) and (
        any(value is None for value in replacement) or args.header_media_partuuid is not None
        or not 0 < args.missing_devid < 2**64
        or re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", args.missing_member_uuid) is None
        or args.missing_member_uuid == "00000000-0000-0000-0000-000000000000"
    ):
        parser.error("mirror replacement requires the new storage selection, header backup, independent slot, "
                     "and missing Btrfs device ID and UUID")
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
