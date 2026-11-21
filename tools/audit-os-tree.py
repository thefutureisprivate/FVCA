#!/usr/bin/env python3
"""Audit an FVCA OS tree or finalize and audit the tree when invoked by mkosi."""

import argparse
import errno
from fnmatch import fnmatchcase
import os
from pathlib import Path
import stat
import sys


SPECIAL_BITS = stat.S_ISUID | stat.S_ISGID
COMMAND_DIRECTORIES = {
    "bin", "sbin", "usr/bin", "usr/sbin", "usr/libexec", "usr/lib/openssh",
    "usr/local/bin", "usr/local/sbin", "usr/local/libexec",
}
FORBIDDEN_COMMANDS = (
    "ash", "bash", "busybox", "csh", "dash", "fish", "ksh", "mksh", "nu", "sh", "tcsh", "toybox", "zsh",
    "awk", "gawk", "mawk", "nawk", "guile*", "java", "julia", "lua*", "node", "nodejs", "perl",
    "perl[0-9]*", "php*", "pwsh", "pypy*", "python*", "R", "Rscript", "raku", "ruby*", "tclsh*", "wish*",
    "dropbear*", "sshd", "sulogin", "su", "sudo*", "doas", "pkexec",
    "apt*", "apk", "bootc", "dnf*", "flatpak", "microdnf", "ostree", "pacman", "rpm", "rpm-ostree",
    "yum", "zypper", "cargo", "cc", "c++", "clang*", "g++*", "gcc*", "gdb", "gdb-*", "gdbserver",
    "lldb*", "make", "rustc",
)


def normalize_build_files(root):
    # PID 1 runs these utilities with the mount privilege already assigned.
    for name in ("mount", "umount"):
        tool = root / "usr/bin" / name
        mode = tool.lstat().st_mode
        if not stat.S_ISREG(mode):
            raise ValueError(f"expected a regular file for /usr/bin/{name}")
        tool.chmod(stat.S_IMODE(mode) & ~SPECIAL_BITS)

    # Unit metadata is public. A private checkout umask must not change its image permissions.
    units = ["emergency.service"]
    if os.path.lexists(root / "etc/initrd-release"):
        units.extend(["fvca-selinux-check.service", "sysroot.mount.d/10-fvca-selinux.conf"])
        if (root / "usr/lib/fvca/activate-runtime").is_file():
            units.extend([
                "fvca-activate-runtime.service",
                "initrd-parse-etc.service.d/20-fvca-runtime.conf",
                "initrd-switch-root.service.d/20-fvca-runtime.conf",
            ])
        if (root / "usr/lib/fvca/activate-guest-data").is_file():
            units.extend([
                "fvca-activate-guest-data.service",
                "initrd-switch-root.service.d/20-fvca-guest-data.conf",
            ])
        if (root / "usr/lib/fvca/activate-oci-runtime").is_file():
            units.extend([
                "fvca-activate-oci-runtime.service",
                "initrd-parse-etc.service.d/21-fvca-oci-runtime.conf",
                "initrd-switch-root.service.d/21-fvca-oci-runtime.conf",
            ])
    else:
        units.extend(["fvca-base-ready.service", "fvca-base.target"])
        if (root / "usr/lib/fvca/activate-workload").is_file():
            units.extend([
                "fvca-workload-root.service", "fvca-workload-start.service",
                "fvca-stage-workload.service", "fvca-trial-workload.service",
                "fvca-discover-workload.service", "fvca-workload-update.timer",
                "fvca-qemu-guest-agent.service",
            ])
            for path in ("usr/lib/fvca/qemu-guest-agent.conf", "usr/lib/udev/rules.d/99-fvca-qemu-guest-agent.rules"):
                (root / path).chmod(0o644)
    for name in units:
        unit = root / "usr/lib/systemd/system" / name
        if not stat.S_ISREG(unit.lstat().st_mode):
            raise ValueError(f"expected a regular file for /usr/lib/systemd/system/{name}")
        unit.chmod(0o644)


def has_file_capability(path):
    try:
        os.getxattr(path, "security.capability", follow_symlinks=False)
    except OSError as error:
        if error.errno == errno.ENODATA:
            return False
        raise
    return True


def raise_walk_error(error):
    raise error


def audit(root):
    violations = []
    count = 0
    for directory, _, names in os.walk(root, onerror=raise_walk_error):
        parent = Path(directory)
        command_directory = parent.relative_to(root).as_posix() in COMMAND_DIRECTORIES
        for name in names:
            path = parent / name
            label = f"/{path.relative_to(root)}"
            if command_directory and any(fnmatchcase(name, pattern) for pattern in FORBIDDEN_COMMANDS):
                violations.append(f"{label} ships a prohibited command")

            mode = path.lstat().st_mode
            if not stat.S_ISREG(mode):
                continue
            count += 1
            if mode & SPECIAL_BITS:
                violations.append(f"{label} has setuid or setgid bits")
            if has_file_capability(path):
                violations.append(f"{label} has file capabilities")
            if mode & 0o111:
                with path.open("rb") as stream:
                    if stream.read(2) == b"#!":
                        violations.append(f"{label} is an executable interpreter script")

    return count, sorted(violations)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tree", nargs="?", type=Path, help="audit an existing OS tree without changing it")
    args = parser.parse_args()
    buildroot = os.environ.get("BUILDROOT")
    if args.tree is None and not buildroot:
        parser.error("provide a tree to audit or invoke this script through mkosi")
    root = (args.tree or Path(buildroot)).resolve()

    try:
        if not root.is_dir() or not (root / "usr/lib/systemd/systemd").is_file():
            raise ValueError(f"expected an FVCA OS tree at {root}")
        if args.tree is None:
            normalize_build_files(root)
        count, violations = audit(root)
        if violations:
            print("FVCA OS tree audit failed", *violations, sep="\n", file=sys.stderr)
            return 1
    except (OSError, ValueError) as error:
        print(f"FVCA OS tree audit failed: {error}", file=sys.stderr)
        return 1

    print(f"FVCA OS tree audit passed ({count} regular files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
