#!/usr/bin/env python3
"""Qualify OpenTofu-managed commissioning on the signed FVCA Host in nested KVM."""

import argparse
from contextlib import contextmanager
from hashlib import file_digest
import json
import os
from pathlib import Path
import re
import runpy
import secrets
import shutil
import socket
import subprocess
import tempfile
import time


TESTS = Path(__file__).resolve().parent
STORAGE = runpy.run_path(str(TESTS / "check-storage.py"))
GUEST = "e629aa43-af11-47c6-aedc-a2dc47f1cc3a"
COMMISSIONED = b"FVCA_GUEST_DATA_COMMISSIONED "
GUEST_READY = b"FVCA_SERVICE_GUEST_READY"
AGENT_READY = b"FVCA_SERVICE_GUEST_AGENT_READY"
LAUNCH = rb"launch-guest\[[0-9]+\]: FVCA_KVM_GUEST_CONFINED"


@contextmanager
def boot(args, members, port, log):
    with STORAGE["software_tpm"](args.tpm_state) as tpm, log.open("xb", buffering=0) as serial:
        command = [
            "qemu-system-x86_64", "-nodefaults", "-machine", "q35,smm=on,kernel_irqchip=split", "-accel", "kvm",
            "-cpu", "Skylake-Client,vmx=on,hle=off,rtm=off", "-m", "8192", "-smp", "4", "-no-reboot",
            "-device", "virtio-rng-pci",
            "-global", "driver=cfi.pflash01,property=secure,value=on",
            "-drive", f"if=pflash,format=raw,readonly=on,file={STORAGE['image'](args.firmware)}",
            "-drive", f"if=pflash,format=raw,snapshot=on,file={STORAGE['image'](args.variables)}",
            "-drive", f"if=none,id=boot,format=raw,snapshot=on,file={STORAGE['image'](args.disk)}",
            "-device", "nvme,drive=boot,serial=fvca-slot-1,logical_block_size=4096,physical_block_size=4096,bootindex=1",
            "-chardev", f"socket,id=chrtpm,path={tpm}", "-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
            "-device", "tpm-tis,tpmdev=tpm0", "-display", "none", "-serial", "stdio", "-monitor", "none",
            "-netdev", f"user,id=management,restrict=on,hostfwd=tcp:127.0.0.1:{port}-10.0.2.15:8443",
            "-device", "igb,netdev=management,addr=06.0,mac=52:54:00:35:5e:01,romfile=",
        ]
        for side, member in zip("ab", members, strict=True):
            command.extend((
                "-drive", f"if=none,id={side},format=raw,file={STORAGE['image'](member)}",
                "-device", f"virtio-blk-pci,drive={side},serial=fvca-member-{side}",
            ))
        with subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=serial, stderr=serial) as process:
            try:
                yield process
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=10)


def wait_for(process, log, marker, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        output = STORAGE["rejoin_serial_output"](log.read_bytes())
        if STORAGE["FAIL"] in output or process.poll() is not None:
            break
        if marker in output:
            return
        time.sleep(0.25)
    raise ValueError(f"the signed Host did not reach {marker.decode()} in {log.name}")


def require_readiness(log, slot, initial):
    serial = log.read_bytes()
    for denial in re.findall(rb"avc:\s+denied[^\r\n]+", serial):
        if ((b'comm="systemd-veritys"' in denial and b'/run/systemd/io.systemd.PCRExtend' in denial)
                or (b'fvca_management_broker_t:' in denial and b'dev="cgroup2"' in denial)):
            raise ValueError(f"an unexpected measurement or cgroup access was denied in {log.name}")
    output = STORAGE["rejoin_serial_output"](serial)
    required = (b"secureboot: Secure boot enabled", b"FVCA_SELINUX_ENFORCING",
                b"FVCA_HYPERVISOR_EPOCH_ACCEPTED ", b"FVCA_HOST_STORAGE_TPM_UNLOCKED",
                STORAGE["HOST_AUTHENTICATED"], STORAGE["HOST_PROFILES"], slot, STORAGE["KERNEL_SEALED"],
                b"FVCA_MANAGEMENT_SOCKET_ENROLLED ", b"FVCA_LIBVIRT_LIFECYCLE_OK", AGENT_READY, GUEST_READY)
    missing = [marker.decode() for marker in required if marker not in output]
    if missing or len(re.findall(LAUNCH, output)) != 1 or output.count(COMMISSIONED) != int(initial):
        raise ValueError(f"unexpected nested Guest boot evidence, missing {missing}")
    if not output.find(STORAGE["KERNEL_SEALED"]) < output.find(AGENT_READY) < output.find(GUEST_READY):
        raise ValueError("the Host did not seal its policy before verifying Guest readiness")
    if initial and not 0 <= output.find(STORAGE["READY"]) < output.find(COMMISSIONED) < output.find(AGENT_READY):
        raise ValueError("the initial Guest reached readiness outside the commissioning sequence")


def qualify(args):
    lab = args.lab
    policy = json.loads((lab / "management.json").read_bytes())
    if policy["address"] != "10.0.2.15:8443" or re.fullmatch("[0-9a-f]{64}", args.bundle_sha256) is None:
        raise ValueError("the test requires its enrolled private management interface and exact Guest bundle root")
    with args.seed.open("rb") as seed:
        seed_hash = file_digest(seed, "sha256").hexdigest()
    inputs = {"bundle_sha256": args.bundle_sha256, "seed_sha256": seed_hash,
              "disk_bytes": args.seed.stat().st_size, "vcpus": 2, "memory_mib": 2048}
    gpt = runpy.run_path(str(TESTS / "check-hypervisor-gpt-slots.py"))
    _, parts = gpt["layout"](args.disk, 4096)
    slot = f"FVCA_HYPERVISOR_SLOT_VERIFIED {parts['fvca-esp'][1]}".encode()
    args.output.mkdir(mode=0o700)
    with socket.socket() as port_finder:
        port_finder.bind(("127.0.0.1", 0))
        port = port_finder.getsockname()[1]

    with tempfile.TemporaryDirectory(prefix="state-", dir=lab) as scratch, (
        args.output / "runner.log"
    ).open("x", encoding="utf-8") as transcript:
        work = Path(scratch)
        members = tuple(work / f"member-{side}.raw" for side in "ab")
        for member in members:
            subprocess.run(["cp", "--reflink=auto", "--sparse=always", "--", lab / "mirror" / member.name,
                            member], check=True)
        shutil.copytree(TESTS.parent / "opentofu" / "examples" / "plan", work / "examples" / "plan",
                        ignore=shutil.ignore_patterns(".terraform", "*.tfstate*", "*.tfplan"))
        shutil.copytree(TESTS.parent / "opentofu" / "modules", work / "modules")
        example = work / "examples" / "plan"
        cli = work / "tofu.rc"
        cli.write_text('provider_installation {\n  filesystem_mirror {\n'
                       f'    path = {json.dumps(str(lab / "tofu-mirror"))}\n'
                       '    include = ["registry.opentofu.org/thefutureisprivate/fvca"]\n  }\n}\n')
        environment = dict(os.environ, TF_CLI_CONFIG_FILE=str(cli), TF_VAR_state_passphrase=secrets.token_hex(32),
                           FVCA_MANAGEMENT_CA_FILE=str(lab / "tls" / "ca.pem"),
                           FVCA_OPERATOR_KEY_FILE=str(lab / "keys" / "operator.key"),
                           TF_VAR_manage_guest="false",
                           TF_VAR_guest=json.dumps({"id": GUEST, "vcpus": 2, "memory_mib": 2048}),
                           TF_VAR_initial_disk=json.dumps(inputs),
                           TF_VAR_host=json.dumps({"id": policy["host"], "address": f"127.0.0.1:{port}",
                                                   "server_name": (lab / "server-name").read_text().strip(),
                                                   "tls_certificate_sha256": policy["tls_certificate_sha256"]}))
        environment.pop("FVCA_PROVISION_OPERATOR_KEY_FILE", None)

        def tofu(*command, expect=None):
            result = subprocess.run(["tofu", f"-chdir={example}", command[0], "-no-color", *command[1:]],
                                    text=True, capture_output=True, env=environment, timeout=45)
            output = result.stdout + result.stderr
            transcript.write(output)
            transcript.flush()
            if expect is None and result.returncode != 0:
                raise ValueError(f"OpenTofu {command[0]} failed. See runner.log")
            if expect is not None and (result.returncode == 0 or expect not in output):
                raise ValueError(f"OpenTofu {command[0]} did not refuse the test case. See runner.log")
            return result.stdout

        tofu("init", "-lockfile=readonly", "-input=false")
        first = args.output / "initial.log"
        with boot(args, members, port, first) as process:
            wait_for(process, first, STORAGE["READY"], 125)
            wrong = dict(inputs, seed_sha256=("0" if seed_hash[0] != "0" else "1") + seed_hash[1:])
            tofu("plan", "-input=false", f"-var=initial_disk={json.dumps(wrong)}",
                 expect="signed Host offer differs")
            tofu("plan", "-input=false", "-out=guest.tfplan")
            tofu("apply", "-input=false", "guest.tfplan", expect="FVCA_PROVISION_OPERATOR_KEY_FILE")
            before = first.read_bytes()
            if COMMISSIONED in before or GUEST_READY in before or re.search(LAUNCH, before):
                raise ValueError("the Guest started before authorized apply")
            (example / "guest.tfplan").unlink()
            tofu("plan", "-input=false", "-out=guest.tfplan")
            environment["FVCA_PROVISION_OPERATOR_KEY_FILE"] = str(lab / "keys" / "commission_operator.key")
            tofu("apply", "-input=false", "guest.tfplan")
            environment.pop("FVCA_PROVISION_OPERATOR_KEY_FILE")
            (example / "guest.tfplan").unlink()
            admission = json.loads(tofu("output", "-json", "provisioning_operation"))
            if admission["state"] not in ("pending", "ready") or re.fullmatch("[0-9a-f]{64}", admission["id"]) is None:
                raise ValueError("apply did not return a durable commissioning identity")
            wait_for(process, first, GUEST_READY, 120)
            require_readiness(first, slot, initial=True)
            tofu("apply", "-refresh-only", "-auto-approve", "-input=false")
            ready = {"id": admission["id"], "state": "ready"}
            if json.loads(tofu("output", "-json", "provisioning_operation")) != ready:
                raise ValueError("refresh did not report the admitted Guest operation ready")
            tofu("plan", "-destroy", "-input=false", expect="Guest retirement requires separate authorization")

        cold = args.output / "cold.log"
        with boot(args, members, port, cold) as process:
            wait_for(process, cold, GUEST_READY, 145)
            wait_for(process, cold, STORAGE["READY"], 15)
            require_readiness(cold, slot, initial=False)
            tofu("apply", "-refresh-only", "-auto-approve", "-input=false")
            if json.loads(tofu("output", "-json", "provisioning_operation")) != ready:
                raise ValueError("a cold boot lost the original commissioning receipt")
    print(f"OpenTofu created and retained the verified Guest operation {ready['id']}.", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("disk", "firmware", "variables", "tpm-state", "lab", "seed", "output"):
        parser.add_argument(f"--{option}", type=lambda path: Path(path).resolve(), required=True)
    parser.add_argument("--bundle-sha256", required=True)
    try:
        qualify(parser.parse_args())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Managed Guest commissioning qualification failed: {error}\n")


if __name__ == "__main__":
    main()
