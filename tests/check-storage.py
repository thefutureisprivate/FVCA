#!/usr/bin/env python3
"""Qualify the signed storage boot paths with disposable lab disks."""

import argparse
from contextlib import contextmanager
import os
from pathlib import Path
import re
import selectors
import shutil
import subprocess
import tempfile
import time


READY = b"FVCA_DEV_BASE_READY"
FAIL = b"FVCA_BOOT_FAILED"
ACTIVE = b"FVCA_HOST_STORAGE_ACTIVE"
PCR_CONFINED = b"FVCA_SELINUX_PCR_CONFINED"
PROMPT = re.compile(rb"Please enter (?:the )?passphrase for disk [^\r\n]{1,250}:|Enter FVCA storage TPM PIN:")
OVMF_CODE = Path("/usr/share/edk2/ovmf/OVMF_CODE.secboot.fd")


def image(path):
    path = path.resolve(strict=True)
    if not path.is_file() or "," in str(path):
        raise ValueError("QEMU inputs must be regular files with comma-free paths")
    return str(path)


def boot(args, name, password, *members, firmware=OVMF_CODE, tpm_socket=None, extra_cmdline=False):
    cpu = "host,vmx=off" if args.guest else "host"
    machine = "q35,smm=on"
    devices = []
    if firmware != OVMF_CODE:
        cpu = "Skylake-Client,vmx=on,hle=off,rtm=off"
        machine += ",kernel_irqchip=split"
        devices = ["-device", "virtio-rng-pci"]
    command = [
        "qemu-system-x86_64", *devices, "-machine", machine, "-accel", "kvm", "-cpu", cpu,
        "-m", "2048", "-smp", "2", "-global", "driver=cfi.pflash01,property=secure,value=on",
        "-drive", f"if=pflash,format=raw,readonly=on,file={image(firmware)}",
        "-drive", f"if=pflash,format=raw,snapshot=on,file={image(args.variables)}",
        "-drive", f"if=none,id=fvca-boot,format=raw,readonly=on,file={image(args.disk)}",
        "-device", "virtio-blk-pci,drive=fvca-boot,bootindex=1",
    ]
    for index, member in enumerate(members):
        drive = f"fvca-member-{index}"
        command += [
            "-drive", f"if=none,id={drive},format=raw,snapshot=on,file={image(member)}",
            "-device", f"virtio-blk-pci,drive={drive},serial={drive}",
        ]
    command += [
        "-display", "none", "-serial", "stdio", "-monitor", "none", "-nic", "none", "-no-reboot",
    ]
    if args.runtime is not None:
        command += [
            "-drive", f"if=none,id=fvca-runtime,format=raw,readonly=on,file={image(args.runtime)}",
            "-device", "virtio-blk-pci,drive=fvca-runtime",
        ]
    if tpm_socket is not None:
        if "," in str(tpm_socket) or not tpm_socket.is_socket():
            raise ValueError("expected a comma-free local TPM socket")
        command += [
            "-chardev", f"socket,id=chrtpm,path={tpm_socket}",
            "-tpmdev", "emulator,id=tpm0,chardev=chrtpm", "-device", "tpm-tis,tpmdev=tpm0",
        ]
    if extra_cmdline:
        command += ["-smbios", "type=11,value=io.systemd.stub.kernel-cmdline-extra=fvca.unapproved-lab-input=1"]

    output = bytearray()
    prompted = False
    submitted = False
    failed_boot = False
    deadline = time.monotonic() + 80
    log = args.output / f"{name}.log"
    try:
        with log.open("wb", buffering=0) as progress, \
                subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT) as qemu, selectors.DefaultSelector() as poll:
            try:
                poll.register(qemu.stdout, selectors.EVENT_READ)
                while (remaining := deadline - time.monotonic()) > 0 and poll.select(remaining):
                    data = os.read(qemu.stdout.fileno(), 65536)
                    if not data:
                        break
                    output.extend(data)
                    if not submitted:
                        progress.write(data)
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
            safe_output = safe_output.replace(password, b"[redacted test credential]")
        log.write_bytes(safe_output)
    if password is not None and password in output:
        raise ValueError(f"{name} echoed the test credential")
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
        if (not prompted or output.count(PCR_CONFINED) < 2
                or not all(mark in output for mark in (ACTIVE, b"FVCA_LIBVIRT_LIFECYCLE_OK", READY))):
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
    if (prompted or output.count(PCR_CONFINED) < 2 or b"FVCA_GUEST_DATA_ACTIVE" not in output
            or READY not in output or FAIL in output):
        raise ValueError("the signed Guest did not boot with its Btrfs data partition")
    print("guest passed")

    prompted, output = boot(args, "guest-missing-disk", None)
    if (prompted or b"authorized Guest data partition is missing" not in output or FAIL not in output
            or READY in output or b"FVCA_GUEST_DATA_ACTIVE" in output):
        raise ValueError("the signed Guest did not fail closed with its data disk absent")
    print("guest-missing-disk passed")


@contextmanager
def software_tpm(state):
    with tempfile.TemporaryDirectory(prefix="fvca-swtpm-") as directory:
        root = Path(directory)
        private = root / "state"
        if state is None:
            private.mkdir(mode=0o700)
        else:
            shutil.copytree(state, private, ignore=shutil.ignore_patterns("socket", "*.lock"))
        socket = root / "control"
        command = [
            "swtpm", "socket", "--tpm2", "--tpmstate", f"dir={private}",
            "--ctrl", f"type=unixio,path={socket}",
        ]
        with subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as emulator:
            try:
                deadline = time.monotonic() + 5
                while not socket.is_socket() and emulator.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.05)
                if not socket.is_socket():
                    raise ValueError("the software TPM did not expose a control socket")
                yield socket
            finally:
                emulator.terminate()
                emulator.wait(timeout=10)


def check_tpm(args):
    pin = args.pin_file.read_bytes().strip()
    if re.fullmatch(b"[0-9a-f]{24}", pin) is None:
        raise ValueError("expected a randomly generated 24-hex-character lab PIN")
    wrong = (b"1" if pin.startswith(b"0") else b"0") + pin[1:]
    a, b = (args.lab / f"member-{label}.raw" for label in ("a", "b"))
    args.output.mkdir(mode=0o700)
    approvals = b"FVCA_HOST_STORAGE_TPM_UNLOCKED", ACTIVE, b"FVCA_LIBVIRT_LIFECYCLE_OK", READY
    for name, state, secret, extra in (
        ("approved", args.tpm_state, pin, False),
        ("wrong-pin", args.tpm_state, wrong, False),
        ("different-tpm", None, pin, False),
        ("injected-command-line", args.tpm_state, pin, True),
    ):
        with software_tpm(state) as socket:
            prompted, log = boot(args, name, secret, a, b, firmware=args.firmware,
                                 tpm_socket=socket, extra_cmdline=extra)
        if b"passphrase for disk" in log:
            raise ValueError(f"{name} offered a passphrase fallback")
        if name == "approved":
            if (not prompted or log.count(PCR_CONFINED) < 2
                    or not all(mark in log for mark in approvals) or FAIL in log):
                raise ValueError("the approved TPM, boot state and operator PIN did not unlock storage")
        elif (not prompted or b'activation failed: "/usr/bin/cryptsetup" exited' not in log or FAIL not in log
              or any(mark in log for mark in approvals)):
            raise ValueError(f"{name} did not fail closed at TPM unsealing")
        if extra and b"fvca.unapproved-lab-input=1" not in log:
            raise ValueError("the boot firmware did not pass the injected command line")
        print(f"{name} passed")

    prompted, log = boot(args, "missing-tpm", None, a, b, firmware=args.firmware)
    if (prompted or FAIL not in log or b"TPM resource manager device is required" not in log
            or b"passphrase for disk" in log or any(mark in log for mark in approvals)):
        raise ValueError("boot did not stop before prompting when TPM was absent")
    print("missing-tpm passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("disk", "variables", "lab", "output"):
        parser.add_argument(f"--{option}", type=Path, required=True)
    role = parser.add_mutually_exclusive_group(required=True)
    role.add_argument("--runtime", type=Path, help="signed Hypervisor runtime")
    role.add_argument("--guest", action="store_true", help="qualify the Service Guest data disk")
    for option in ("tpm-state", "pin-file", "firmware"):
        parser.add_argument(f"--{option}", type=Path)
    args = parser.parse_args()
    tpm_options = (args.tpm_state, args.pin_file, args.firmware)
    if any(tpm_options) and (args.guest or not all(tpm_options)):
        parser.error("the Hypervisor TPM test requires --tpm-state, --pin-file and --firmware")
    try:
        if args.tpm_state is not None:
            check_tpm(args)
        elif args.guest:
            check_guest(args)
        else:
            check_hypervisor(args)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Host storage qualification failed: {error}\n")
