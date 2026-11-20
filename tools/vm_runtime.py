"""Keep the reviewed Hypervisor payload and verify that it is additive."""

import os
from pathlib import Path
import re

import runtime_tree


IMAGE_ID = "vm-runtime"
EXECUTABLES = (
    "qemu-img", "qemu-system-x86_64", "restic", "virtlockd", "virtlogd", "virtqemud",
)
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
    Path("usr/lib/systemd/system/fvca-service-guest.service"),
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
