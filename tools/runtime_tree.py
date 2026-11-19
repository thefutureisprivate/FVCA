"""Build and check an additive, shell-free FVCA runtime tree."""

import os
from pathlib import Path
import re
import shutil
import stat


OVERLAY_BOOKKEEPING = {
    f"{namespace}.overlay.{attribute}"
    for namespace in ("trusted", "user")
    for attribute in ("origin", "impure")
}


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


def inspect_tree(root, base, *, allowed, required, prune):
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

    for path in required:
        node = root / path
        if node.is_symlink() or not node.is_file():
            raise ValueError(f"missing regular file /{path}")


def pack(root, base, root_hash, *, binding, inspect):
    if re.fullmatch(r"[0-9a-f]{64}", root_hash) is None:
        raise ValueError("invalid prepared base root hash")
    binding = root / binding
    binding.parent.mkdir(parents=True, exist_ok=True)
    binding.write_text(f"{root_hash}\n", encoding="ascii")
    binding.chmod(0o644)
    inspect(root, base, prune=True)
    if (root / "opt").exists():
        shutil.rmtree(root / "opt")

    # mkfs.erofs reads these from the staging tree. mkosi copies only /usr and /opt.
    contexts = Path("etc/selinux/targeted/contexts/files")
    shutil.copytree(base / contexts, root / contexts, dirs_exist_ok=True)
