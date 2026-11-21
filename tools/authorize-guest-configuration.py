#!/usr/bin/env python3
"""Carry a pending OpenTofu Guest configuration into the signed Host trial path."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
from uuid import UUID

from core_image import inspect_uki
from guest_boot_bundle import SERVICE_GUEST_ID
from guest_configuration import settings_record
from hypervisor_trial import candidate_layout, slot_layout, standing_fields
from runtime_boot import BOOT_EFI, GUEST_CONFIG_ARGUMENT, GUEST_CONFIG_KEY_ARGUMENT, MANAGEMENT_ARGUMENT
from workload_oci import file_record, open_regular, parse_json, read_bytes


ED25519 = bytes.fromhex("302a300506032b6570032100")
HEX = re.compile(r"[0-9a-f]{64}")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def settings(configuration):
    return {"schema": "fvca-service-guest-vm-v2", "guest": SERVICE_GUEST_ID,
            "configuration_revision": configuration["revision"], "vcpus": configuration["vcpus"],
            "memory_mib": configuration["memory_mib"]}


def binding(configuration):
    value = digest(settings_record(settings(configuration)))
    if configuration["sha256"] != value:
        raise ValueError("configuration digest differs from its canonical resource settings")
    return f"{configuration['revision']},{value}"


def intent(outputs, enrollment):
    if not isinstance(outputs, dict) or outputs.keys() != {
        "active_configuration", "planned_configuration", "configuration_operation",
    }:
        raise ValueError("expected the three Guest configuration outputs from OpenTofu")
    active, planned, operation = (outputs[name] for name in (
        "active_configuration", "planned_configuration", "configuration_operation",
    ))
    host = enrollment["host"]
    if (enrollment["schema"] != "fvca-hypervisor-management-v1" or str(UUID(host)) != host
            or UUID(host).int == 0 or host == SERVICE_GUEST_ID
            or planned["host_id"] != host or planned["guest_id"] != SERVICE_GUEST_ID):
        raise ValueError("configuration outputs differ from the enrolled Host or Guest identity")
    submitter = enrollment.get("apply_operator_public_key", "")
    if not HEX.fullmatch(submitter) or int(submitter, 16) == 0:
        raise ValueError("the Host enrollment lacks a configuration submitter key")
    if (planned["activation"] != "host-trial" or operation is None
            or operation["state"] != "pending-activation" or operation["host_trial"] is not False):
        raise ValueError("expected a pending Host trial configuration on a stable slot")
    if active["revision"] is None and active["sha256"] is None:
        resources = (active["vcpus"], active["memory_mib"])
        if any(type(value) is not int for value in resources) or resources != (2, 2048):
            raise ValueError("default Guest configuration differs from its approved resources")
        previous = None
    else:
        previous = binding(active)
    next_binding = binding(planned)
    if planned["revision"] != (active["revision"] or 0) + 1:
        raise ValueError("Guest configuration must advance by exactly one revision")
    prior = previous or "default"
    identity = (f"FVCA-GUEST-CONFIGURATION-INTENT-1\nhost={host}\nguest={SERVICE_GUEST_ID}\n"
                f"previous={prior}\nnext={next_binding}\n").encode("ascii")
    if operation["id"] != digest(identity):
        raise ValueError("operation ID differs from the active and planned Guest configuration")
    return previous, next_binding, settings(planned)


def argument(cmdline, name):
    items = [word.partition("=")[2] for word in cmdline.split() if word.partition("=")[0] == name]
    if len(items) > 1 or items == [""]:
        raise ValueError(f"invalid or duplicate signed UKI argument {name}")
    return items[0] if items else None


def uki(image, offset, certificate, target):
    subprocess.run(["mcopy", "-i", f"{image}@@{offset}", BOOT_EFI, target], check=True, timeout=60)
    info = file_record(target, 256 * 1024**2)
    cmdline = inspect_uki(target, certificate)[".cmdline"]["text"]
    return cmdline, info


def require_arguments(cmdline, expected):
    for name, value in expected.items():
        if argument(cmdline, name) != value:
            raise ValueError(f"signed UKI has a different {name} binding")


def verify(key, signature, payload, work):
    public, detached, document = (work / name for name in ("public.der", "signature", "document"))
    public.write_bytes(ED25519 + key)
    detached.write_bytes(signature)
    document.write_bytes(payload)
    subprocess.run(["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-keyform", "DER", "-inkey", public,
                    "-sigfile", detached, "-in", document], check=True, stdout=subprocess.DEVNULL, timeout=30)


def epoch(value):
    if re.fullmatch(r"[1-9][0-9]{0,19}", value) is None or int(value) >= 2**64:
        raise ValueError("invalid standing trial epoch or validity time")
    return int(value)


def authorize(args, enrollment, previous, next_binding, work, stable_disk, candidate_disk):
    packet = read_bytes(args.trial, 2048)
    standing, trial = standing_fields(packet[64:])
    stable_parts, stable_offset, _ = slot_layout(stable_disk, args.sector_size)
    stable, _ = uki(stable_disk, stable_offset, args.boot_certificate, work / "stable.efi")
    trial_pin = argument(stable, "fvca.trial_key")
    if not trial_pin or not HEX.fullmatch(trial_pin) or int(trial_pin, 16) == 0:
        raise ValueError("the stable UKI lacks its standing trial authority")
    verify(bytes.fromhex(trial_pin), packet[:64], packet[64:], work)

    beginning, expiry = (epoch(standing[name]) for name in ("not_before", "expires"))
    if not 0 < expiry - beginning <= 86400 or not beginning <= int(time.time()) < expiry:
        raise ValueError("standing trial is outside its signed validity interval")
    from_epoch, to_epoch = (epoch(standing[name]) for name in ("stable_epoch", "candidate_epoch"))
    if from_epoch > to_epoch or any(HEX.fullmatch(standing[key]) is None for key in (
        "epoch_policy_sha256", "stable_core", "stable_runtime", "stable_guest_bundle", "candidate_uki_sha256",
    )) or any(HEX.fullmatch(trial[key]) is None for key in (
        "candidate_core", "candidate_runtime", "guest_bundle", "candidate_esp_sha256",
    )):
        raise ValueError("invalid standing trial release epochs or epoch policy")
    stable_entry, _, stable_esp = trial["stable"].partition(",")
    candidate_entry, _, candidate_esp = trial["candidate"].partition(",")
    if (stable_entry == candidate_entry or stable_esp == candidate_esp or stable_esp != stable_parts["esp"]
            or any(re.fullmatch(r"[0-9a-f]{4}", entry) is None for entry in (stable_entry, candidate_entry))
            or str(UUID(trial["transaction"])) != trial["transaction"]):
        raise ValueError("standing trial does not select the reviewed stable and candidate slots")
    esp, devices, candidate_offset = candidate_layout(candidate_disk, args.sector_size, trial)
    if esp != trial["candidate_esp_sha256"] or any(standing[key] != value for key, value in devices.items()):
        raise ValueError("candidate ESP or payload partition identities differ from the standing trial")
    candidate, image = uki(candidate_disk, candidate_offset, args.boot_certificate, work / "candidate.efi")
    if (image["digest"] != f"sha256:{standing['candidate_uki_sha256']}"
            or str(image["size"]) != standing["candidate_uki_bytes"]):
        raise ValueError("candidate UKI differs from the exact standing trial image")

    public = subprocess.check_output(["openssl", "pkey", "-in", args.configuration_key, "-pubout", "-outform", "DER"],
                                     timeout=30)
    if len(public) != len(ED25519) + 32 or not public.startswith(ED25519):
        raise ValueError("Guest configuration requires an Ed25519 signing key")
    key = public[len(ED25519):]
    if key.hex() == trial_pin:
        raise ValueError("configuration and standing trial authorities must use distinct keys")
    common = {MANAGEMENT_ARGUMENT: digest(enrollment), GUEST_CONFIG_KEY_ARGUMENT: key.hex(), "fvca.trial_key": trial_pin}
    policy = standing["epoch_policy_sha256"]
    require_arguments(stable, {**common, GUEST_CONFIG_ARGUMENT: previous, "fvca.hypervisor_trial": None,
                               "fvca.hypervisor_epoch": f"{from_epoch},{policy}", "roothash": standing["stable_core"]})
    require_arguments(candidate, {**common, GUEST_CONFIG_ARGUMENT: next_binding,
                                  "fvca.hypervisor_trial": trial["transaction"],
                                  "fvca.hypervisor_epoch": f"{to_epoch},{policy}", "roothash": trial["candidate_core"]})

    body = (f"FVCA-GUEST-CONFIGURATION-CHANGE-1\nguest={SERVICE_GUEST_ID}\ntrial_sha256={digest(packet)}\n"
            f"previous={previous or 'default'}\nnext={next_binding}\n").encode("ascii")
    document = work / "approval"
    document.write_bytes(body)
    signature = subprocess.check_output(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", args.configuration_key,
                                         "-in", document], timeout=30)
    verify(key, signature, body, work)
    if not beginning <= int(time.time()) < expiry:
        raise ValueError("standing trial expired during configuration signing")
    return signature + body


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="action", required=True)
    for action in ("prepare", "authorize"):
        mode = modes.add_parser(action)
        for name in ("outputs", "enrollment", "output"):
            mode.add_argument(f"--{name}", type=Path, required=True)
        if action == "authorize":
            for name in ("stable", "candidate", "boot-certificate", "trial", "configuration-key"):
                mode.add_argument(f"--{name}", type=Path, required=True)
            mode.add_argument("--sector-size", type=int, choices=(512, 4096), default=4096)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        enrollment = read_bytes(args.enrollment, 4096)
        previous, next_binding, values = intent(parse_json(read_bytes(args.outputs, 4096)), parse_json(enrollment))
        with tempfile.TemporaryDirectory(prefix=".fvca-guest-config-", dir=args.output.parent) as directory:
            work = Path(directory)
            if args.action == "prepare":
                data = (json.dumps(values, indent=2) + "\n").encode("ascii")
            else:
                descriptors = Path(f"/proc/{os.getpid()}/fd")
                with open_regular(args.stable) as stable, open_regular(args.candidate) as candidate:
                    data = authorize(args, enrollment, previous, next_binding, work,
                                     descriptors / str(stable.fileno()), descriptors / str(candidate.fileno()))
            staged = work / "output"
            with staged.open("xb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.link(staged, args.output)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(1, f"FVCA Guest configuration handoff failed: {error}\n")


if __name__ == "__main__":
    main()
