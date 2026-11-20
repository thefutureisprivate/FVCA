"""Keep the reviewed Hypervisor payload and verify that it is additive."""

import os
from pathlib import Path
import re

import runtime_tree


IMAGE_ID = "vm-runtime"
EXECUTABLES = (
    "mtools", "qemu-img", "qemu-system-x86_64", "restic", "sbverify", "virtlockd", "virtlogd", "virtqemud",
)
MCOPY = Path("usr/bin/mcopy")
RELEASE_CLIENT = Path("usr/libexec/fvca/release-client")
LIBVIRT_UNITS = {
    Path(f"usr/lib/systemd/system/fvca-{daemon}.{kind}")
    for daemon in ("virtqemud", "virtlogd", "virtlockd")
    for kind in ("service", "socket")
}
DOMAIN_SCHEMAS = {
    Path(f"usr/share/libvirt/schemas/{name}.rng")
    for name in ("basictypes", "cputypes", "domain", "domaincommon", "domainoverrides",
                 "domainsnapshot", "inactiveDomain", "networkcommon", "nwfilter_params",
                 "privatedata", "storagecommon", "sysinfocommon")
}
BASE_INPUT = "vm-runtime-base"
TRIAL_HEALTH = Path("usr/libexec/fvca/trial-health")
TRIAL_HEALTH_WATCHDOG = Path("usr/libexec/fvca/trial-health-watchdog-v2")
GUEST_TRIAL_FILES = (
    Path("usr/bin/systemd-dissect"),
    Path("usr/lib/systemd/system/fvca-verify-guest-trial.service"),
    Path("usr/lib/systemd/system/fvca-activate-guest-trial.service"),
    Path("usr/lib/systemd/system/fvca-guest-trial-attempt.service"),
)
GUEST_UPDATE_UNITS = tuple(
    Path(f"usr/lib/systemd/system/fvca-guest-os-update.{kind}") for kind in ("service", "timer")
)
FIRMWARE_UPDATE_UNITS = tuple(
    Path(f"usr/lib/systemd/system/{unit}") for unit in (
        "fvca-firmware-update.service", "fvca-firmware-update.timer", "fvca-firmware-recovery.service",
    )
)
FIRMWARE_UPDATE_SUPPORT = Path("usr/lib/fvca/firmware-update-support-v11")
BASE_BINDING = Path("usr/share/fvca/vm-runtime-base.roothash")
EXTENSION_RELEASE = Path("usr/lib/extension-release.d/extension-release.vm-runtime")
REQUIRED_FILES = {
    *(Path("usr/bin") / name for name in EXECUTABLES),
    *LIBVIRT_UNITS,
    *DOMAIN_SCHEMAS,
    Path("usr/lib/tmpfiles.d/fvca-libvirt.conf"),
    Path("usr/libexec/fvca/qualify-libvirt"),
    Path("usr/libexec/fvca/launch-guest"),
    Path("usr/libexec/fvca/backup-worker"),
    RELEASE_CLIENT,
    Path("usr/lib64/fvca/fat-gconv/IBM437.so"),
    Path("usr/lib64/fvca/fat-gconv/gconv-modules"),
    Path("usr/share/fvca/mtools.conf"),
    Path("usr/lib/systemd/system/fvca-service-guest.service"),
    Path("usr/lib/systemd/system/fvca-activate-hypervisor-trial.service"),
    Path("usr/lib/systemd/system/fvca-host-update.service"),
    Path("usr/lib/systemd/system/fvca-host-update.timer"),
    Path("usr/lib/systemd/system/fvca-recover-hypervisor-activation.service"),
    Path("usr/lib/systemd/system/fvca-guest-failure.service"),
    Path("usr/lib/systemd/system/fvca-capture-stopped@.service"),
    Path("usr/lib/systemd/system/fvca-capture-live@.service"),
    Path("usr/lib/systemd/system/fvca-capture-list.service"),
    Path("usr/lib/systemd/system/fvca-capture-inspect@.service"),
    Path("usr/lib/systemd/system/fvca-capture-expire@.service"),
    Path("usr/lib/systemd/system/fvca-capture-retention.service"),
    Path("usr/lib/systemd/system/fvca-capture-retention.timer"),
    Path("usr/lib/systemd/system/fvca-live-window@.service"),
    Path("usr/lib/systemd/system/fvca-live-recover@.service"),
    Path("usr/lib/systemd/system/fvca-live-recover@.timer"),
    Path("usr/lib/systemd/system/fvca-restore-guest@.service"),
    Path("usr/lib/systemd/system/fvca-backup-live@.service"),
    Path("usr/lib/systemd/system/fvca-backup-stopped@.service"),
    Path("usr/lib/systemd/system/fvca-backup-health.service"),
    Path("usr/lib/systemd/system/fvca-backup-health.timer"),
    Path("usr/lib/systemd/system/fvca-backup-scheduled.service"),
    Path("usr/lib/systemd/system/fvca-backup-upload@.service"),
    Path("usr/lib/systemd/system/fvca-backup-download@.service"),
    Path("usr/lib/systemd/system/fvca-restore-s3@.service"),
    Path("usr/lib/systemd/system/fvca-backup.slice"),
    Path("usr/libexec/libvirt_iohelper"),
    Path("usr/lib64/libvirt/connection-driver/libvirt_driver_qemu.so"),
    Path("usr/lib64/libvirt/lock-driver/lockd.so"),
    Path("usr/share/libvirt/cpu_map/index.xml"),
    Path("usr/share/edk2/ovmf/OVMF_CODE.secboot.fd"),
    Path("usr/share/edk2/ovmf/OVMF_VARS.fd"),
    Path("usr/share/seabios/bios-256k.bin"),
    Path("usr/share/qemu/linuxboot_dma.bin"),
    EXTENSION_RELEASE,
    BASE_BINDING,
}
FIRMWARE_DATA = {
    Path("usr/share/qemu/kvmvapic.bin"),
    Path("usr/share/qemu/firmware/41-edk2-ovmf-2m-raw-x64-sb.json"),
    Path("usr/share/seavgabios/vgabios-stdvga.bin"),
}


def allowed(path):
    return (
        path in REQUIRED_FILES
        or path == MCOPY
        or path in (TRIAL_HEALTH, TRIAL_HEALTH_WATCHDOG)
        or path in GUEST_TRIAL_FILES
        or path in GUEST_UPDATE_UNITS
        or path in FIRMWARE_UPDATE_UNITS
        or path == FIRMWARE_UPDATE_SUPPORT
        or path in FIRMWARE_DATA
        or path.is_relative_to("usr/share/licenses")
        or (path.parent == Path("usr/share/libvirt/cpu_map") and path.suffix == ".xml")
        or (
            path.parent == Path("usr/lib64")
            and re.fullmatch(r"lib(?!python|nss_)[\w+.-]+\.so(?:\.[0-9]+)*", path.name) is not None
        )
    )


def inspect_tree(root, base, *, prune):
    if os.path.lexists(base / "usr/lib/fvca/role"):
        raise ValueError("VM runtime requires the common core")
    runtime_tree.inspect_tree(root, base, allowed=allowed, required=REQUIRED_FILES, prune=prune)
    if not (root / MCOPY).is_symlink() or os.readlink(root / MCOPY) != "mtools":
        raise ValueError("the EFI reader must be the signed relative mtools link")
