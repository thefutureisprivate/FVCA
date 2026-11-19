#!/usr/bin/env python3
"""Keep the reviewed Hypervisor payload and verify that it is additive."""

import os
from pathlib import Path
import re
import shutil
import stat
import sys


EXECUTABLES = (
    "qemu-img", "qemu-system-x86_64", "restic", "virtlockd", "virtlogd", "virtqemud",
)
LIBVIRT_UNITS = {
    Path(f"usr/lib/systemd/system/fvca-{daemon}.{kind}")
    for daemon in ("virtqemud", "virtlogd", "virtlockd")
    for kind in ("service", "socket")
}
BASE_BINDING = Path("usr/share/fvca/vm-runtime-base.roothash")
EXTENSION_RELEASE = Path("usr/lib/extension-release.d/extension-release.vm-runtime")
REQUIRED_FILES = {
    *(Path("usr/bin") / name for name in EXECUTABLES),
    *LIBVIRT_UNITS,
    Path("usr/lib/tmpfiles.d/fvca-libvirt.conf"),
    Path("usr/libexec/fvca/qualify-libvirt"),
    Path("usr/libexec/libvirt_iohelper"),
    Path("usr/lib64/libvirt/connection-driver/libvirt_driver_qemu.so"),
    Path("usr/lib64/libvirt/lock-driver/lockd.so"),
    Path("usr/share/libvirt/cpu_map/index.xml"),
    Path("usr/share/edk2/ovmf/OVMF_CODE.secboot.fd"),
    Path("usr/share/edk2/ovmf/OVMF_VARS.fd"),
    EXTENSION_RELEASE,
    BASE_BINDING,
}
FIRMWARE_DATA = {
    Path("usr/share/qemu/kvmvapic.bin"),
    Path("usr/share/qemu/firmware/41-edk2-ovmf-2m-raw-x64-sb.json"),
    Path("usr/share/seavgabios/vgabios-stdvga.bin"),
}
OVERLAY_BOOKKEEPING = {
    f"{namespace}.overlay.{attribute}"
    for namespace in ("trusted", "user")
    for attribute in ("origin", "impure")
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


def raise_walk_error(error):
    raise error


def check_metadata(node, path, mode, *, prune):
    xattrs = set(os.listxattr(node, follow_symlinks=False))
    if prune and stat.S_ISDIR(mode):
        # mkosi used overlayfs while installing. Directory origin markers
        # belong to that build overlay and must stay out of the image.
        for name in xattrs & OVERLAY_BOOKKEEPING:
            os.removexattr(node, name, follow_symlinks=False)
            xattrs.remove(name)
    blocked = sorted(
        x for x in xattrs
        if x == "security.capability" or x.startswith(("trusted.overlay.", "user.overlay."))
    )
    if blocked:
        raise ValueError(f"/{path} has prohibited extended attributes: {blocked}")
    if mode & (stat.S_ISUID | stat.S_ISGID):
        raise ValueError(f"/{path} has a set-user-ID or set-group-ID bit")


def inspect_tree(root, base, *, prune):
    usr = root / "usr"
    if usr.is_symlink() or not usr.is_dir():
        raise ValueError("expected a real /usr directory")
    check_metadata(usr, "usr", usr.stat().st_mode, prune=prune)

    for directory, children, files in os.walk(usr, topdown=False, onerror=raise_walk_error):
        parent = Path(directory)
        for name in children + files:
            node = parent / name
            path = node.relative_to(root)
            mode = node.lstat().st_mode
            base_node = base / path
            if stat.S_ISDIR(mode):
                if prune and not any(node.iterdir()):
                    node.rmdir()
                    continue
                if os.path.lexists(base_node) and (base_node.is_symlink() or not base_node.is_dir()):
                    raise ValueError(f"/{path} would shadow a non-directory base path")
            else:
                if not allowed(path):
                    if not prune:
                        raise ValueError(f"unexpected payload /{path}")
                    node.unlink()
                    continue
                if os.path.lexists(base_node):
                    raise ValueError(f"/{path} would replace a base path")
                if not (stat.S_ISREG(mode) or stat.S_ISLNK(mode)):
                    raise ValueError(f"/{path} has an unsupported file type")

            check_metadata(node, path, mode, prune=prune)
            if stat.S_ISREG(mode) and mode & 0o111:
                with node.open("rb") as stream:
                    if stream.read(2) == b"#!":
                        raise ValueError(f"/{path} is an executable interpreter script")

    for node in usr.rglob("*"):
        if node.is_symlink():
            if Path(os.readlink(node)).is_absolute() or not node.resolve(strict=True).is_relative_to(usr):
                raise ValueError(f"/{node.relative_to(root)} points outside the extension")

    for path in REQUIRED_FILES:
        node = root / path
        if node.is_symlink() or not node.is_file():
            raise ValueError(f"missing regular file /{path}")


def pack(root, base, root_hash):
    if re.fullmatch(r"[0-9a-f]{64}", root_hash) is None:
        raise ValueError("invalid prepared base root hash")
    binding = root / BASE_BINDING
    binding.parent.mkdir(parents=True, exist_ok=True)
    binding.write_text(f"{root_hash}\n", encoding="ascii")
    binding.chmod(0o644)
    inspect_tree(root, base, prune=True)
    if (root / "opt").exists():
        shutil.rmtree(root / "opt")

    # mkfs.erofs reads these from the staging tree. mkosi copies only /usr and /opt.
    contexts = Path("etc/selinux/targeted/contexts/files")
    shutil.copytree(base / contexts, root / contexts, dirs_exist_ok=True)


def main():
    buildroot = Path(os.environ["BUILDROOT"])
    prepared = Path(os.environ["SRCDIR"]) / "build/vm-runtime-base"
    try:
        pack(buildroot, prepared / "root", (prepared / "roothash").read_text(encoding="ascii").strip())
    except (OSError, ValueError, RuntimeError) as error:
        sys.exit(f"FVCA runtime payload rejected: {error}")
    print("FVCA Hypervisor payload is additive and shell-free")


if __name__ == "__main__":
    main()
