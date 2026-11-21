#!/usr/bin/env python3
"""Qualify the signed storage boot paths with disposable lab disks."""

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import subprocess
import sys
import tempfile
import time


READY = b"FVCA_DEV_BASE_READY"
FAIL = b"FVCA_BOOT_FAILED"
KERNEL_SEALED = b"FVCA_KERNEL_POLICY_SEALED"
ACTIVE = b"FVCA_HOST_STORAGE_ACTIVE"
HOST_PROFILES = b"FVCA_BTRFS_PROFILES raid1 raid1 raid1"
HOST_AUTHENTICATED = b"FVCA_HOST_STORAGE_AUTHENTICATED"
GUEST_PROFILES = b"FVCA_BTRFS_PROFILES single dup dup"
DIRECT_ACTIVE = b"FVCA_DIRECT_BOOT_POLICY_ACTIVE"
DIRECT_MISMATCH = b"direct-boot kernel command line differs from the signed command line"
INIT_EXIT = b"Attempted to kill init! exitcode=0x00000100"
PCR_CONFINED = b"FVCA_SELINUX_PCR_CONFINED"
PROMPT = re.compile(rb"Please enter (?:the )?passphrase for disk [^\r\n]{1,250}:|Enter FVCA storage TPM PIN:")
KERNEL_AUDIT = re.compile(rb"\[ *[0-9]+\.[0-9]+\] audit: type=[0-9]+ audit\([0-9]+\.[0-9]+:[0-9]+\): [^\r\n]*\r?\n")
KERNEL_MOUNT_NOTICE = re.compile(rb"\[ *[0-9]+\.[0-9]+\] (?:BTRFS info|erofs) \(device [^\r\n]*\r?\n")
OVMF_CODE = Path("/usr/share/edk2/ovmf/OVMF_CODE.secboot.fd")


def rejoin_serial_output(output):
    return KERNEL_MOUNT_NOTICE.sub(b"", KERNEL_AUDIT.sub(b"", output))


def image(path):
    path = path.resolve(strict=True)
    if not path.is_file() or "," in str(path):
        raise ValueError("QEMU inputs must be regular files with comma-free paths")
    return str(path)


def boot(args, name, password, *members, firmware=OVMF_CODE, tpm_socket=None, extra_cmdline=False,
         attach_runtime=True, timeout=80, direct_cmdline=None, attach_guest=True, ready_marker=READY,
         firmware_timeout=None, allow_reboot=False):
    cpu = "host,vmx=off" if args.guest else "host"
    machine = "q35,smm=on"
    devices = []
    bundle = getattr(args, "direct_boot", None)
    nested = getattr(args, "nested_guest", None)
    persistent = getattr(args, "persistent_boot", False)
    state_access = "" if persistent else "snapshot=on,"
    if bundle is None:
        loader = [
            "-global", "driver=cfi.pflash01,property=secure,value=on",
            "-drive", f"if=pflash,format=raw,readonly=on,file={image(firmware)}",
            "-drive", f"if=pflash,format=raw,{state_access}file={image(args.variables)}",
        ]
    else:
        machine = "pc-q35-11.1"
        loader = [
            "-kernel", image(bundle / "linux"), "-initrd", image(bundle / "initrd"),
            "-append", args.direct_cmdline if direct_cmdline is None else direct_cmdline,
        ]
    if bundle is None and firmware != OVMF_CODE:
        cpu = "Skylake-Client,vmx=on,hle=off,rtm=off"
        machine += ",kernel_irqchip=split"
        devices = ["-device", "virtio-rng-pci"]
    if getattr(args, "no_default_devices", False):
        devices.append("-nodefaults")
    if getattr(args, "trial_watchdog", False):
        devices += ["-device", "i6300esb", "-action", "watchdog=reset"]
    nvme = getattr(args, "nvme_boot", False)
    sector = getattr(args, "boot_sector_size", 512)
    geometry = f",logical_block_size={sector},physical_block_size={sector}" if nvme or sector != 512 else ""
    boot_device = "nvme,drive=fvca-boot,serial=fvca-slot-1" if nvme else "virtio-blk-pci,drive=fvca-boot"
    media_access = "snapshot=on" if nvme else "readonly=on"
    command = [
        "qemu-system-x86_64", *devices, "-machine", machine, "-accel", "kvm", "-cpu", cpu,
        "-m", str(getattr(args, "memory_mib", 4096 if nested is not None else 2048)),
        "-smp", str(getattr(args, "vcpus", 2)), *loader,
        "-drive", f"if=none,id=fvca-boot,format=raw,{media_access},file={image(args.disk)}",
        "-device", f"{boot_device}{geometry}" + ("" if persistent else ",bootindex=1"),
    ]
    for index, member in enumerate(members):
        drive = f"fvca-member-{index}"
        member_access = "" if getattr(args, "persistent_members", False) else state_access
        command += [
            "-drive", f"if=none,id={drive},format=raw,{member_access}file={image(member)}",
            "-device", f"virtio-blk-pci,drive={drive},serial={drive}",
        ]
    command += [
        "-display", "none", "-serial", "stdio", "-monitor", "none", "-nic", "none",
    ]
    if not allow_reboot:
        command.append("-no-reboot")
    if getattr(args, "qmp_path", None) is not None:
        command += ["-qmp", f"unix:{args.qmp_path},server=on,wait=off"]
    if args.runtime is not None and attach_runtime:
        companion = "nvme,drive=fvca-runtime,serial=fvca-slot-2" if nvme else "virtio-blk-pci,drive=fvca-runtime"
        command += [
            "-drive", f"if=none,id=fvca-runtime,format=raw,{media_access},file={image(args.runtime)}",
            "-device", f"{companion}{geometry}",
        ]
    if nested is not None and attach_guest:
        command += [
            "-drive", f"if=none,id=fvca-guest-release,format=raw,readonly=on,file={image(nested)}",
            "-device", "virtio-blk-pci,drive=fvca-guest-release",
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

    ready = ready_marker if isinstance(ready_marker, re.Pattern) else re.compile(re.escape(ready_marker))
    output = bytearray()
    prompts = 0
    prompt_start = 0
    waiting_for_no_echo = False
    submitted = False
    failed_boot = False
    deadline = time.monotonic() + (timeout if firmware_timeout is None else firmware_timeout)
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
                    if firmware_timeout is not None and b"Kernel command line:" in output:
                        deadline = time.monotonic() + timeout
                        firmware_timeout = None
                    if not submitted:
                        progress.write(data)
                    recent = output[max(prompt_start, len(output) - 4096):]
                    if not waiting_for_no_echo and PROMPT.search(recent) and b"(press TAB for no echo)" in recent:
                        prompts += 1
                        waiting_for_no_echo = True
                        if password is not None:
                            qemu.stdin.write(b"\t")
                            qemu.stdin.flush()
                    if waiting_for_no_echo and password is not None and b"(no echo) " in recent:
                        # The prompt is printed before the terminal switches off echo.
                        qemu.stdin.write(password + b"\r")
                        submitted = True
                        waiting_for_no_echo = False
                        prompt_start = len(output)
                        qemu.stdin.flush()
                    if (ready.search(output) or ready.search(rejoin_serial_output(output[-4096:]))
                            or (direct_cmdline is not None and (DIRECT_MISMATCH in output or INIT_EXIT in output))):
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
    return prompts, output


def check_hypervisor(args):
    lab = args.lab
    password = (lab / "storage.key").read_bytes()
    if re.fullmatch(b"[0-9a-f]{64}", password) is None:
        raise ValueError("unexpected lab passphrase encoding")
    member_a, member_b = (lab / f"member-{label}.raw" for label in ("a", "b"))
    policy = lab / "host-storage.conf"
    authenticated = policy.is_file() and b"\nprotection=luks2-xts-hmac-sha256\n" in policy.read_bytes()
    args.output.mkdir(mode=0o700)

    def boot_case(options, name, key, *members):
        if not authenticated:
            return boot(options, name, key, *members)
        options.no_default_devices = True
        for attempt in range(1, 4):
            prompted, log = boot(options, f"{name}-{attempt}", key, *members, firmware_timeout=36, timeout=105)
            if b"Kernel command line:" in log:
                break
        log = rejoin_serial_output(log)
        return prompted, log

    cases = [("healthy", args, member_a, member_b)]
    if authenticated:
        cases.append(("crash-recovered", args, lab / "crash-member-a.raw", lab / "crash-member-b.raw"))
    if args.replacement_disk is not None:
        rebuilt_args = argparse.Namespace(**vars(args))
        rebuilt_args.disk = args.replacement_disk
        cases.append(("rebuilt", rebuilt_args, lab / "surviving-member.raw", lab / "replacement.raw"))
    for name, boot_args, a, b in cases:
        prompts, output = boot_case(boot_args, name, password, a, b)
        if (prompts != 2 or output.count(PCR_CONFINED) < 2 or FAIL in output
                or not all(mark in output for mark in (HOST_PROFILES, ACTIVE, b"FVCA_LIBVIRT_LIFECYCLE_OK", READY))
                or (authenticated and not 0 <= output.find(HOST_AUTHENTICATED) < output.find(HOST_PROFILES))):
            raise ValueError(f"{name} did not boot with the encrypted mirror")
        if not 0 <= output.find(KERNEL_SEALED) < output.find(READY):
            raise ValueError(f"{name} reached readiness without sealing the Hypervisor kernel policy")
        print(f"{name} passed")

    wrong = (b"1" if password.startswith(b"0") else b"0") + password[1:]
    refusals = [
        ("wrong-passphrase", wrong, (member_a, member_b), b"development passphrase unlock exited"),
        ("missing-member-a", None, (member_b,), b"both authorized storage members are required"),
        ("missing-member-b", None, (member_a,), b"both authorized storage members are required"),
        ("duplicate-member", None, (member_a, member_a), b"more than one device has the authorized partition UUID"),
        ("unselected-replacement", None, (member_a, lab / "replacement.raw"), b"both authorized storage members are required"),
        ("wrong-luks-identity", None, (member_a, lab / "wrong-luks.raw"), b"storage superblock does not match the signed selection"),
    ]
    if authenticated:
        refusals.extend((
            ("plain-luks-substitution", password, (member_a, lab / "plain-member-b.raw"),
             b"authenticated Host storage requires a journal over the selected partition"),
            ("damaged-authenticated-sectors", password,
             (lab / "damaged-member-a.raw", lab / "damaged-member-b.raw"), b"INTEGRITY AEAD ERROR"),
        ))
    for name, key, devices, reason in refusals:
        prompted, output = boot_case(args, name, key, *devices)
        expected_prompts = int(key is not None) + int(name in ("plain-luks-substitution", "damaged-authenticated-sectors"))
        if (prompted != expected_prompts or FAIL not in output or reason not in output
                or any(mark in output for mark in (ACTIVE, READY, HOST_PROFILES))):
            raise ValueError(f"{name} did not fail closed")
        if name == "plain-luks-substitution" and HOST_AUTHENTICATED in output:
            raise ValueError("the unauthenticated member passed the authenticated mapping gate")
        if name == "damaged-authenticated-sectors" and HOST_AUTHENTICATED not in output:
            raise ValueError("the damaged sectors were not tested through the verified mappings")
        print(f"{name} passed")


def require_nested_guest_ready(log, required, expected_launches):
    guest_ready = b"FVCA_SERVICE_GUEST_READY"
    guest_agent = b"FVCA_SERVICE_GUEST_AGENT_READY"
    guests = re.findall(rb"launch-guest\[[0-9]+\]: FVCA_KVM_GUEST_CONFINED", log)
    probe = re.search(rb"qualify-libvirt\[[0-9]+\]: FVCA_KVM_GUEST_CONFINED", log)
    mandatory = (HOST_PROFILES, ACTIVE, b"FVCA_LIBVIRT_LIFECYCLE_OK", guest_agent, guest_ready, READY)
    if len(guests) != expected_launches or probe is None or FAIL in log or any(
        marker not in log for marker in (*mandatory, *required)
    ):
        raise ValueError("the Hypervisor did not reach readiness with its authorized nested Guest")
    if not 0 <= log.find(KERNEL_SEALED) < log.find(guest_agent) < log.find(guest_ready) < log.find(READY):
        raise ValueError("the Hypervisor did not seal its policy and verify Guest agent readiness in order")


def check_nested_guest_tpm_auto(args):
    """Qualify a self-contained slot with freshly copied software TPM state."""
    args.output.mkdir(mode=0o700)
    args.nvme_boot = True
    args.boot_sector_size = 4096
    args.no_default_devices = True
    args.memory_mib = 8192
    args.vcpus = 4
    members = [args.lab / f"member-{side}.raw" for side in ("a", "b")]
    for attempt in range(1, 4):
        with software_tpm(args.tpm_state) as socket:
            prompts, log = boot(
                args, f"nested-tpm-auto-{attempt}", None, *members, firmware=args.firmware,
                tpm_socket=socket, firmware_timeout=30, timeout=155, ready_marker=READY,
            )
        if b"Kernel command line:" in log:
            break
    log = rejoin_serial_output(log)
    if prompts or PROMPT.search(log):
        raise ValueError("the unattended Hypervisor requested storage input")
    epoch = b"FVCA_HYPERVISOR_EPOCH_ACCEPTED"
    unlocked = b"FVCA_HOST_STORAGE_TPM_UNLOCKED"
    required = (
        b"secureboot: Secure boot enabled", b"FVCA_HYPERVISOR_SLOT_VERIFIED", epoch, HOST_AUTHENTICATED,
        b"FVCA_HOST_STORAGE_UNLOCK_PROFILE tpm2-auto", unlocked,
    )
    require_nested_guest_ready(log, required, expected_launches=1)
    if not 0 <= log.find(epoch) < log.find(unlocked) < log.find(ACTIVE):
        raise ValueError("the Hypervisor did not enforce its TPM epoch before publishing storage")
    print("nested-guest-tpm-auto passed")


def check_nested_guest(args):
    args.output.mkdir(mode=0o700)
    lab = args.lab
    password = (lab / "storage.key").read_bytes()
    if re.fullmatch(b"[0-9a-f]{64}", password) is None:
        raise ValueError("unexpected lab passphrase encoding")
    members = [lab / f"member-{member}.raw" for member in ("a", "b")]
    guest_ready = b"FVCA_SERVICE_GUEST_READY"
    finished = READY
    if args.nested_guest_shutdown:
        finished = b"FVCA_NESTED_STOP_VERIFIED"
    if args.nested_guest_capture:
        finished = b"FVCA_STOPPED_CAPTURE_VERIFIED"
    if args.nested_guest_live_capture:
        finished = b"FVCA_LIVE_CAPTURE_VERIFIED"
    if args.nested_guest_restore:
        finished = b"FVCA_COLD_RESTORE_VERIFIED"
    timeout = 300 if args.nested_guest_restore else (225 if args.nested_guest_capture else 155)
    prompts, log = boot(args, "guest", password, *members, timeout=timeout,
                        ready_marker=finished)
    # Kernel audit printing can interrupt a userspace line on the shared console.
    # Validate the reconstructed markers and retain the original log on disk.
    log = rejoin_serial_output(log)
    required = ()
    if args.nested_guest_shutdown:
        required += (b"FVCA_SERVICE_GUEST_STOPPED", finished)
    if args.nested_guest_capture:
        required += (b"FVCA_SERVICE_GUEST_STOPPED", finished)
    if args.nested_guest_live_capture or args.nested_guest_restore:
        required += (finished,)
    expected_launches = 4 if args.nested_guest_restore else (2 if args.nested_guest_capture else 1)
    require_nested_guest_ready(log, required, expected_launches)
    if prompts != 2:
        raise ValueError("the passphrase Hypervisor did not unlock the two expected members")
    print("nested-guest passed")
    if args.nested_guest_shutdown:
        print("nested-guest-shutdown passed")
    if args.nested_guest_capture:
        seal = log.find(b"FVCA_CAPTURE_SEALED_PENDING_VALIDATION ff6b9317-4240-4635-a6d9-94e557cb83c8 ")
        resume = log.find(b"FVCA_CAPTURE_GUEST_RESUMED ff6b9317-4240-4635-a6d9-94e557cb83c8")
        complete = tuple(re.finditer(rb"FVCA_CAPTURE_COMPLETE ff6b9317-4240-4635-a6d9-94e557cb83c8 ([0-9a-f]{64})", log))
        stopped = re.search(rb"FVCA_CAPTURE_COMPLETE a51a4aa4-20c3-437c-af18-3ebae71123fc [0-9a-f]{64}", log)
        if (len(complete) != 2 or complete[0][1] != complete[1][1] or stopped is None or
                not 0 <= seal < resume < complete[0].start() < complete[1].start() < stopped.start() or
                log.count(guest_ready) != 2 or log.count(b"FVCA_CAPTURE_GUEST_RESUMED") != 1):
            raise ValueError("stopped capture ordering, finalization recovery or stopped-state preservation failed")
        print("nested-guest-stopped-capture passed")
    if args.nested_guest_live_capture:
        capture = b"619e7cf7-3660-452b-bcbb-7de8da0361e1"
        events = (b"LIVE_GUEST_FROZEN", b"LIVE_DISK_INACTIVE", b"LIVE_SNAPSHOT_CREATED",
                  b"CAPTURE_SEALED_PENDING_VALIDATION", b"LIVE_VM_RESUMED", b"LIVE_GUEST_THAWED",
                  b"LIVE_GUEST_RECOVERED")
        markers = [b"FVCA_" + event + b" " + capture for event in events]
        positions = [log.find(marker) for marker in markers]
        complete = tuple(re.finditer(rb"FVCA_CAPTURE_COMPLETE " + capture + rb" ([0-9a-f]{64})", log))
        if (positions[0] < 0 or any(left >= right for left, right in zip(positions, positions[1:]))
                or any(log.count(marker) != 1 for marker in markers) or len(complete) != 2
                or positions[-1] >= complete[0].start() or complete[0][1] != complete[1][1]
                or log.count(guest_ready) != 1 or b"FVCA_SERVICE_GUEST_STOPPED" in log):
            raise ValueError("live capture ordering, finalization recovery or running-state preservation failed")
        print("nested-guest-live-capture passed")
    if args.nested_guest_restore:
        live = b"b43ad128-b5a0-4d85-b3f0-29fb32b08b8a.cf92ad0c-6ccd-4562-8663-c39e31ede807"
        stopped = b"9c0db5ae-03da-4136-a93a-f981c71dedfb.a4bbcc0d-c47d-4031-ad38-ba76ef3ebe9a"
        empty = b"9c0db5ae-03da-4136-a93a-f981c71dedfb.863333ec-9e20-4f6a-8f08-d636cd99e466"
        verified = b"FVCA_RESTORE_VERIFIED "
        captured = b"FVCA_CAPTURE_COMPLETE 9b5c817b-c896-4d9a-b664-b962468fd00c"
        if (log.count(verified + live) != 2 or log.count(verified + stopped) != 1
                or log.count(verified + empty) != 1 or log.count(captured) != 1
                or not log.find(verified + live) < log.find(verified + stopped) < log.find(verified + empty) < log.find(captured)
                or b"cold restore requires the Service Guest to be stopped" not in log
                or log.count(guest_ready) != expected_launches):
            raise ValueError("cold restore failed its identity, idempotency or running-Guest checks")
        print("nested-guest-cold-restore passed")

    prompts, log = boot(args, "missing-bundle", password, *members, attach_guest=False)
    if (prompts != 2 or b"authorized Guest boot bundle partitions are missing" not in log or FAIL not in log
            or guest_ready in log or READY in log):
        raise ValueError("the Hypervisor did not fail closed with its selected Guest bundle absent")
    print("nested-guest-missing-bundle passed")

    nocow = [lab / f"nocow-{member}.raw" for member in ("a", "b")]
    prompts, log = boot(args, "guest-nocow", password, *nocow)
    if (prompts != 2 or b"Btrfs inode disables CoW or data checksums" not in log or FAIL not in log
            or guest_ready in log or READY in log):
        raise ValueError("the Hypervisor did not reject the Guest's NOCOW disk")
    print("nested-guest-nocow passed")


def check_guest(args):
    args.output.mkdir(mode=0o700)
    data = args.lab / "guest-data.raw"
    prompted, output = boot(args, "guest", None, data)
    if (prompted or output.count(PCR_CONFINED) < 2 or GUEST_PROFILES not in output or b"FVCA_GUEST_DATA_ACTIVE" not in output
            or READY not in output or FAIL in output):
        raise ValueError("the signed Guest did not boot with its Btrfs data partition")
    if args.oci_runtime is not None and not all(marker in output for marker in (
        b"FVCA_OCI_RUNTIME_ACTIVE", b"FVCA_OCI_RUNTIME_EXEC_OK", b"FVCA_PODMAN_INFO crun vfs true",
        b"--rootfs /run/fvca/oci-probe-root",
    )):
        raise ValueError("the signed Guest did not execute its OCI runtime or render the approved Quadlet fixture")
    if args.oci_runtime is not None and not 0 <= output.find(KERNEL_SEALED) < output.find(READY):
        raise ValueError("the Service Guest reached readiness without sealing its kernel policy")
    if args.direct_boot is not None:
        check_direct_boot(args, output, data)
    print("guest passed")

    for name, disks, reason in (
        ("guest-missing-disk", (), b"authorized Guest data partition is missing"),
        ("guest-wrong-profile", (args.lab / "guest-wrong-profile.raw",), b"Btrfs metadata allocation must use only dup"),
    ):
        prompted, output = boot(args, name, None, *disks)
        if prompted or reason not in output or FAIL not in output or READY in output or b"FVCA_GUEST_DATA_ACTIVE" in output:
            raise ValueError(f"{name} did not fail closed before data activation")
        print(f"{name} passed")

    if args.oci_runtime is None:
        return
    missing = b"authorized OCI runtime partitions are missing"
    cases = [
        ("guest-missing-runtime", (), False, missing),
        ("guest-duplicate-runtime", (args.oci_runtime,), True, b"more than one device has the authorized partition UUID"),
    ]
    if args.wrong_runtime is not None:
        cases.append(("guest-wrong-runtime", (args.wrong_runtime,), False, missing))
    for name, extras, attach, reason in cases:
        prompted, output = boot(args, name, None, data, *extras, attach_runtime=attach)
        if (prompted or FAIL not in output or reason not in output or READY in output
                or b"FVCA_OCI_RUNTIME_ACTIVE" in output):
            raise ValueError(f"{name} did not fail closed before runtime activation")
        print(f"{name} passed")


def check_direct_boot(args, output, data):
    if DIRECT_ACTIVE not in output or f"FVCA_OCI_RUNTIME_ACTIVE {args.direct_runtime}".encode() not in output:
        raise ValueError("the verified direct-boot policy and bound runtime did not activate")
    extra = "fvca.test-extra=1"
    prompts, output = boot(args, "guest-direct-command-line", None, data, timeout=25,
                           direct_cmdline=f"{args.direct_cmdline} {extra}")
    # A failing early PID 1 can panic before its complete stderr line drains.
    # The unchanged control boot already proved that this exact bundle works.
    rejected = DIRECT_MISMATCH in output or INIT_EXIT in output
    if prompts or extra.encode() not in output or not rejected or DIRECT_ACTIVE in output or READY in output:
        raise ValueError("the direct-boot Guest did not reject the unexpected command line")
    print("guest-direct-command-line passed")


def check_guest_workload(args):
    args.output.mkdir(mode=0o700)
    active = b"FVCA_WORKLOAD_ROOT_ACTIVE"
    selection = Path(__file__).with_name("guest-storage.conf").read_text(encoding="ascii")
    filesystem = next(line.partition("=")[2] for line in selection.splitlines() if line.startswith("filesystem_uuid="))
    mount = f"first mount of filesystem {filesystem}".encode("ascii")
    for name, failure in (
        ("approved", None),
        ("tampered", b"workload artifact does not match the signed bytes"),
    ):
        deadline = 220 if args.stalwart_lifecycle else 125
        prompted, output = boot(args, name, None, args.lab / f"{name}.raw", timeout=deadline)
        output = rejoin_serial_output(output)
        # The kernel and service streams can interleave on the serial console.
        if prompted or not (mount in output or b"FVCA_GUEST_DATA_ACTIVE" in output) or b"FVCA_WORKLOAD_KEYRING_SEALED" not in output:
            raise ValueError(f"{name} did not reach the workload admission boundary")
        if args.direct_boot is not None and DIRECT_ACTIVE not in output:
            raise ValueError(f"{name} did not activate the signed direct-boot policy")
        if failure is None:
            if any(marker not in output for marker in (active, b"FVCA_WORKLOAD_STARTED", READY)) or FAIL in output:
                raise ValueError("the authorized workload did not mount and start in the signed Guest")
            if args.stalwart_lifecycle:
                check_stalwart_lifecycle(output)
            if args.stalwart_mail:
                started = output.find(b"FVCA_WORKLOAD_STARTED")
                compared = output.find(b"FVCA_STALWART_MAIL_COMPARE")
                verified = output.find(b"FVCA_STALWART_MAIL_VERIFIED")
                if not 0 <= started < compared < verified < output.find(READY):
                    raise ValueError("the configured Stalwart mailbox was not verified before Guest readiness")
        elif failure not in output or FAIL not in output or READY in output or active in output:
            raise ValueError("the tampered workload did not fail before activation")
        print(f"workload-{name} passed")

    if args.stalwart_mail_mismatch is not None:
        check_stalwart_mail_mismatch(args)


def check_stalwart_mail_mismatch(args):
    from guest_boot_bundle import verify

    bundle = args.stalwart_mail_mismatch
    cmdline, release = verify(bundle, args.release_certificate)
    original = args.direct_release
    fixed_files = ("cmdline", "domain.xml", "linux", "runtime.raw")
    if (release["core_root"] != original["core_root"]
            or release["runtime_root"] != original["runtime_root"]
            or any(release["files"][name] != original["files"][name] for name in fixed_files)
            or release["files"]["initrd"] == original["files"]["initrd"]):
        raise ValueError("the mailbox mismatch bundle must preserve the Guest core, runtime and boot policy")

    mismatch = argparse.Namespace(**vars(args))
    mismatch.direct_boot = bundle
    mismatch.direct_cmdline = cmdline
    mismatch.disk = bundle / "core.raw"
    mismatch.runtime = bundle / "runtime.raw"
    prompts, output = boot(mismatch, "wrong-mail-reference", None, args.lab / "approved.raw", timeout=125)
    output = rejoin_serial_output(output)
    started = output.find(b"FVCA_WORKLOAD_STARTED")
    compared = output.find(b"FVCA_STALWART_MAIL_COMPARE")
    if (prompts or DIRECT_ACTIVE not in output or not 0 <= started < compared < output.find(FAIL)
            or b"FVCA_STALWART_MAIL_VERIFIED" in output or READY in output):
        raise ValueError("the Guest did not reject the wrong reference after retrieving the authenticated message")
    print("workload-wrong-mail-reference passed")


def check_guest_workload_stage(args):
    args.output.mkdir(mode=0o700)
    grant = args.workload_stage.read_bytes()
    record = json.loads(grant)
    expected = " ".join((
        "sha256:" + hashlib.sha256(grant).hexdigest(),
        record["from_authorization"], record["to_authorization"],
    )).encode()
    with tempfile.TemporaryDirectory(prefix="stage-disk-", dir=args.output) as directory:
        data = Path(directory) / "guest-data.raw"
        subprocess.run(
            ["cp", "--reflink=auto", "--sparse=always", "--", args.lab / "approved.raw", data],
            check=True,
        )
        args.persistent_members = True
        for phase in ("published", "retained"):
            marker = b"FVCA_WORKLOAD_STAGED " + phase.encode() + b" " + expected
            receipt = re.compile(re.escape(marker) + rb" ([0-9]+)[\r\n]")
            prompts, output = boot(args, phase, None, data, timeout=140, ready_marker=receipt)
            output = rejoin_serial_output(output)
            found = receipt.search(output)
            if (prompts or DIRECT_ACTIVE not in output or FAIL in output or found is None
                    or not 0 <= output.find(b"FVCA_WORKLOAD_STARTED") < found.start()
                    or not 0 < int(found[1]) <= record["expires"]):
                raise ValueError(f"the signed workload stage was not {phase} after starting the active workload")
            print(f"workload-stage-{phase} passed", flush=True)

    args.persistent_members = False
    failure = b"workload artifact does not match the signed bytes"
    prompts, output = boot(args, "tampered-workload-stage", None, args.lab / "tampered.raw",
                           timeout=140, ready_marker=failure)
    output = rejoin_serial_output(output)
    if (prompts or DIRECT_ACTIVE not in output or FAIL in output or b"FVCA_WORKLOAD_STAGED" in output
            or not 0 <= output.find(b"FVCA_WORKLOAD_STARTED") < output.find(failure)):
        raise ValueError("the Guest did not reject the changed candidate while keeping the active workload")
    print("workload-stage-tampered passed", flush=True)


def check_stalwart_lifecycle(output):
    if not re.search(
        rb"FVCA_STALWART_STATE [a-z_]+:system_r:container_t:s0:c[0-9]+,c[0-9]+ 2000:2000 128 true none healthy",
        output,
    ):
        raise ValueError("Stalwart did not run with the approved identity, confinement and health state")
    expected = (
        b"MemoryMax=536870912", b"CPUQuotaPerSecUSec=1s", b"TasksMax=128", b"ActiveState=inactive",
        b"FVCA_STALWART_RESTART_HEALTH_AND_DATA", b"FVCA_STALWART_LIFECYCLE_COMPLETE",
    )
    if not all(marker in output for marker in expected) or b"FVCA_STALWART_UNEXPECTED_CONTAINER" in output:
        raise ValueError("Stalwart resource limits, restart, persistence or stop did not qualify")
    values = re.findall(rb"cat\[\d+\]: ([0-9]+(?: [0-9]+)?)\r?\n", output)
    cpu_limits = [list(map(int, value.split())) for value in values if b" " in value]
    if b"536870912" not in values or b"128" not in values or not any(0 < quota == period for quota, period in cpu_limits):
        raise ValueError("the live kernel cgroup does not implement the approved workload budgets")


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
    approvals = b"FVCA_HOST_STORAGE_TPM_UNLOCKED", HOST_PROFILES, ACTIVE, b"FVCA_LIBVIRT_LIFECYCLE_OK", READY
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
            if (prompted != 2 or log.count(PCR_CONFINED) < 2
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
    for option in ("lab", "output"):
        parser.add_argument(f"--{option}", type=Path, required=True)
    loader = parser.add_mutually_exclusive_group(required=True)
    loader.add_argument("--disk", type=Path, help="signed UEFI boot disk")
    loader.add_argument("--direct-boot", type=Path, help="signed direct-boot bundle to qualify")
    parser.add_argument("--variables", type=Path, help="UEFI variable store for --disk")
    parser.add_argument("--release-certificate", type=Path, help="trusted release certificate for --direct-boot")
    role = parser.add_mutually_exclusive_group(required=True)
    role.add_argument("--runtime", type=Path, help="signed Hypervisor runtime")
    role.add_argument("--guest", action="store_true", help="qualify the Service Guest data disk")
    role.add_argument("--oci-runtime", type=Path, help="signed Service Guest OCI runtime")
    role.add_argument("--nested-guest-tpm-auto", action="store_true",
                      help="qualify a signed 4 KiB Hypervisor GPT slot with unattended TPM unlock and its integrated Guest")
    parser.add_argument("--replacement-disk", type=Path, help="Hypervisor boot disk authorizing the lab replacement")
    parser.add_argument("--nested-guest", type=Path, help="Guest bundle to launch inside the disposable Hypervisor")
    qualification = parser.add_mutually_exclusive_group()
    qualification.add_argument("--nested-guest-shutdown", action="store_true",
                               help="require orderly stop with the disposable qualification initramfs")
    qualification.add_argument("--nested-guest-capture", action="store_true",
                               help="require a stopped capture and restart with the disposable qualification initramfs")
    qualification.add_argument("--nested-guest-live-capture", action="store_true",
                               help="require live capture and thaw with the disposable qualification initramfs")
    qualification.add_argument("--nested-guest-restore", action="store_true",
                               help="require cold restore from live and stopped captures")
    parser.add_argument("--wrong-runtime", type=Path, help="unselected runtime for a Guest rejection test")
    workload_qualification = parser.add_mutually_exclusive_group()
    workload_qualification.add_argument("--workload", action="store_true",
                                        help="qualify workload activation with approved.raw and tampered.raw")
    workload_qualification.add_argument("--workload-stage", type=Path,
                                        help="check durable staging for the exact signed transition JSON")
    stalwart = parser.add_mutually_exclusive_group()
    stalwart.add_argument("--stalwart-lifecycle", action="store_true", help="check the disposable Stalwart lifecycle fixture")
    stalwart.add_argument("--stalwart-mail", action="store_true", help="require the authenticated Stalwart mailbox check")
    parser.add_argument("--stalwart-mail-mismatch", type=Path,
                        help="separately signed direct-boot bundle with an intentionally wrong mail reference")
    for option in ("tpm-state", "pin-file", "firmware"):
        parser.add_argument(f"--{option}", type=Path)
    args = parser.parse_args()
    if args.direct_boot is not None:
        if not args.guest or args.variables is not None or args.release_certificate is None:
            parser.error("--direct-boot requires --guest and --release-certificate")
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
        from guest_boot_bundle import verify
        try:
            args.direct_cmdline, args.direct_release = verify(args.direct_boot, args.release_certificate)
            args.direct_runtime = args.direct_release["runtime_root"]
        except (OSError, ValueError, subprocess.CalledProcessError) as error:
            parser.exit(1, f"Direct-boot qualification failed before launch: {error}\n")
        args.disk = args.direct_boot / "core.raw"
        args.oci_runtime = args.direct_boot / "runtime.raw"
    elif args.variables is None or args.release_certificate is not None:
        parser.error("--disk requires --variables")
    if args.wrong_runtime is not None and args.oci_runtime is None:
        parser.error("--wrong-runtime requires --oci-runtime")
    if args.workload and (args.oci_runtime is None or args.wrong_runtime is not None):
        parser.error("--workload requires --oci-runtime and its own Btrfs fixtures")
    if args.workload_stage is not None and (args.direct_boot is None or args.wrong_runtime is not None):
        parser.error("--workload-stage requires --direct-boot and tests a candidate-altered disk")
    if args.stalwart_lifecycle and not args.workload:
        parser.error("--stalwart-lifecycle requires --workload")
    if args.stalwart_mail and not args.workload:
        parser.error("--stalwart-mail requires --workload")
    if args.stalwart_mail_mismatch is not None and (not args.stalwart_mail or args.direct_boot is None):
        parser.error("--stalwart-mail-mismatch requires --stalwart-mail and --direct-boot")
    if args.oci_runtime is not None:
        args.guest = True
        args.runtime = args.oci_runtime
    tpm_options = (args.tpm_state, args.pin_file, args.firmware)
    if args.nested_guest_tpm_auto:
        if not args.tpm_state or not args.firmware or args.pin_file or args.replacement_disk or args.nested_guest:
            parser.error("nested TPM auto-unlock requires --tpm-state and --firmware for an integrated GPT slot")
    elif any(tpm_options) and (args.guest or not all(tpm_options)):
        parser.error("the Hypervisor TPM test requires --tpm-state, --pin-file and --firmware")
    if args.replacement_disk is not None and (args.guest or any(tpm_options)):
        parser.error("--replacement-disk requires the Hypervisor development passphrase test")
    if args.nested_guest is not None and (args.guest or any(tpm_options) or args.replacement_disk is not None):
        parser.error("--nested-guest requires the Hypervisor development passphrase test")
    if (args.nested_guest_shutdown or args.nested_guest_capture or args.nested_guest_live_capture
            or args.nested_guest_restore) and args.nested_guest is None:
        parser.error("nested Guest qualification requires --nested-guest")
    try:
        if args.nested_guest_tpm_auto:
            check_nested_guest_tpm_auto(args)
        elif args.tpm_state is not None:
            check_tpm(args)
        elif args.workload:
            check_guest_workload(args)
        elif args.workload_stage is not None:
            check_guest_workload_stage(args)
        elif args.guest:
            check_guest(args)
        elif args.nested_guest is not None:
            check_nested_guest(args)
        else:
            check_hypervisor(args)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Host storage qualification failed: {error}\n")
