#!/usr/bin/env python3
"""Qualify the signed storage boot paths with disposable lab disks."""

import argparse
import os
from pathlib import Path
import re
import selectors
import subprocess
import time


READY = b"FVCA_DEV_BASE_READY"
FAIL = b"FVCA_BOOT_FAILED"
ACTIVE = b"FVCA_HOST_STORAGE_ACTIVE"
PROMPT = re.compile(rb"Please enter (?:the )?passphrase for disk [^\r\n]{1,250}:")
OVMF_CODE = Path("/usr/share/edk2/ovmf/OVMF_CODE.secboot.fd")


def image(path):
    path = path.resolve(strict=True)
    if not path.is_file() or "," in str(path):
        raise ValueError("QEMU inputs must be regular files with comma-free paths")
    return str(path)


def boot(args, name, password, *members):
    cpu = "host,vmx=off" if args.guest else "host"
    command = [
        "qemu-system-x86_64", "-machine", "q35,smm=on", "-accel", "kvm", "-cpu", cpu,
        "-m", "2048", "-smp", "2", "-global", "driver=cfi.pflash01,property=secure,value=on",
        "-drive", f"if=pflash,format=raw,readonly=on,file={image(OVMF_CODE)}",
        "-drive", f"if=pflash,format=raw,snapshot=on,file={image(args.variables)}",
        "-drive", f"if=virtio,format=raw,snapshot=on,file={image(args.disk)}",
        "-display", "none", "-serial", "stdio", "-monitor", "none", "-nic", "none", "-no-reboot",
    ]
    if args.runtime is not None:
        command += ["-drive", f"if=virtio,format=raw,readonly=on,file={image(args.runtime)}"]
    for member in members:
        command += ["-drive", f"if=virtio,format=raw,snapshot=on,file={image(member)}"]

    output = bytearray()
    prompted = False
    submitted = False
    failed_boot = False
    deadline = time.monotonic() + 80
    try:
        with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT) as qemu, selectors.DefaultSelector() as poll:
            try:
                poll.register(qemu.stdout, selectors.EVENT_READ)
                while (remaining := deadline - time.monotonic()) > 0 and poll.select(remaining):
                    data = os.read(qemu.stdout.fileno(), 65536)
                    if not data:
                        break
                    output.extend(data)
                    recent = output[-4096:]
                    if not prompted and PROMPT.search(recent) and b"(press TAB for no echo)" in recent:
                        prompted = True
                        if password is not None:
                            qemu.stdin.write(b"\t")
                            qemu.stdin.flush()
                    if prompted and password is not None and not submitted and b"(no echo) " in recent:
                        # The prompt is printed before the terminal switches off echo.
                        qemu.stdin.write(password + b"\r")
                        submitted = True
                        qemu.stdin.flush()
                    if READY in output:
                        break
                    if not failed_boot and FAIL in output:
                        failed_boot = True
                        deadline = min(deadline, time.monotonic() + 8)
            finally:
                qemu.terminate()
                try:
                    qemu.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    qemu.kill()
                    qemu.wait()
    finally:
        safe_output = bytes(output)
        if password is not None:
            safe_output = safe_output.replace(password, b"[redacted test passphrase]")
        (args.output / f"{name}.log").write_bytes(safe_output)
    if password is not None and password in output:
        raise ValueError(f"{name} echoed the test passphrase")
    return prompted, output


def check_hypervisor(args):
    lab = args.lab
    password = (lab / "storage.key").read_bytes()
    if re.fullmatch(b"[0-9a-f]{64}", password) is None:
        raise ValueError("unexpected lab passphrase encoding")
    member_a, member_b = (lab / f"member-{label}.raw" for label in ("a", "b"))
    args.output.mkdir(mode=0o700)
    for name, a, b in (
        ("healthy", member_a, member_b),
        ("rebuilt", lab / "surviving-member.raw", lab / "replacement.raw"),
    ):
        prompted, output = boot(args, name, password, a, b)
        if not prompted or not all(mark in output for mark in (ACTIVE, b"FVCA_LIBVIRT_LIFECYCLE_OK", READY)):
            raise ValueError(f"{name} did not boot with the encrypted mirror")
        print(f"{name} passed")

    wrong = (b"1" if password.startswith(b"0") else b"0") + password[1:]
    for name, key, devices, reason in (
        ("wrong-passphrase", wrong, (member_a, member_b), b"development passphrase unlock exited"),
        ("missing-member", None, (member_a,), b"both authorized storage members are required"),
        ("duplicate-member", None, (member_a, member_a), b"more than one device has the authorized partition UUID"),
    ):
        prompted, output = boot(args, name, key, *devices)
        if prompted != (key is not None) or FAIL not in output or reason not in output or ACTIVE in output or READY in output:
            raise ValueError(f"{name} did not fail closed")
        print(f"{name} passed")


def check_guest(args):
    args.output.mkdir(mode=0o700)
    prompted, output = boot(args, "guest", None, args.lab / "guest-data.raw")
    if prompted or b"FVCA_GUEST_DATA_ACTIVE" not in output or READY not in output or FAIL in output:
        raise ValueError("the signed Guest did not boot with its Btrfs data partition")
    print("guest passed")

    prompted, output = boot(args, "guest-missing-disk", None)
    if (prompted or b"authorized Guest data partition is missing" not in output or FAIL not in output
            or READY in output or b"FVCA_GUEST_DATA_ACTIVE" in output):
        raise ValueError("the signed Guest did not fail closed with its data disk absent")
    print("guest-missing-disk passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("disk", "variables", "lab", "output"):
        parser.add_argument(f"--{option}", type=Path, required=True)
    role = parser.add_mutually_exclusive_group(required=True)
    role.add_argument("--runtime", type=Path, help="signed Hypervisor runtime")
    role.add_argument("--guest", action="store_true", help="qualify the Service Guest data disk")
    try:
        args = parser.parse_args()
        if args.guest:
            check_guest(args)
        else:
            check_hypervisor(args)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Host storage qualification failed: {error}\n")
