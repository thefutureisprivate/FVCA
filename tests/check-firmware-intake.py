#!/usr/bin/env python3
"""Qualify Host firmware staging with signed TUF fixtures and no firmware writes."""

import argparse
from copy import deepcopy
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import runpy
import shutil
import subprocess

from securesystemslib.signer import CryptoSigner
from tuf.api.metadata import TargetFile


intake = runpy.run_path(Path(__file__).with_name("check-release-intake.py"))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def observed_device(identity, version, serial=None):
    capsule = identity["component"] != "nvme"
    result = {
        "DeviceId": identity["device_id"], "Name": identity["model"],
        "Plugin": "uefi_capsule" if capsule else "nvme", "Guid": [identity["guid"]],
        "VendorIds": [identity["vendor_id"]], "Protocols": ["org.uefi.capsule" if capsule else "org.nvmexpress"],
        "Version": version["text"], "VersionFormat": identity["version_format"],
        "Flags": ["internal", "updatable", "needs-reboot"],
    }
    if version["raw"] is not None:
        result["VersionRaw"] = version["raw"]
    if serial:
        result["Serial"] = serial
    return result


def qualify(client, output):
    output.mkdir(mode=0o700)
    state = output / "state"
    state.mkdir(mode=0o700)
    depot = output / "depot"
    depot.mkdir()
    (depot / "targets").mkdir()
    config = output / "depot.json"
    intake["write_json"](config, {"transport": "local", "path": str(depot)})
    owner, qualified = (CryptoSigner.generate_ed25519() for _ in range(2))
    key = output / "owner.public"
    key.write_bytes(bytes.fromhex(owner.public_key.keyval["public"]))
    trusted = output / "root.json"
    policy_path = output / "policy.json"
    signature = output / "policy.sig"
    observation = output / "observation.json"
    archive = b"FVCA test fixture bytes. No firmware payload.\n"
    cabinet_name = f"fvca-firmware-{digest(archive)}.cab"
    cabinet = output / cabinet_name
    cabinet.write_bytes(archive)
    catalog = {}
    catalog_targets = {}
    for field, extension in (("metadata", "bin"), ("signature", "jcat")):
        content = f"FVCA catalog fixture {field}\n".encode()
        checksum = digest(content)
        name = f"fvca-firmware-catalog-{checksum}.{extension}"
        path = output / name
        path.write_bytes(content)
        catalog[field] = {"bytes": len(content), "sha256": checksum}
        catalog_targets[name] = path
    platform = {"system_uuid": "1dc9e837-914b-497a-83bc-63c93e741acc", "vendor": "LENOVO",
                "product": "UNIT-TEST", "board": "fixture board", "board_revision": "fixture revision"}
    bios = {"component": "system-firmware", "device_id": "1" * 40,
            "guid": "ed151d94-9d52-4a39-b0aa-c0088fdcaa4f", "model": "System Firmware",
            "vendor_id": "DMI:LENOVO", "serial_sha256": None, "version_format": "pair"}
    nvme = {"component": "nvme", "device_id": "2" * 40, "guid": "4d0aed03-a30c-52c6-99e7-a8977797c3d9",
            "model": "fixture NVMe", "vendor_id": "PCI:0x1179",
            "serial_sha256": digest(b"fixture-NVMe-A"), "version_format": "plain"}
    now = datetime.now(UTC).replace(microsecond=0)
    stamp = int(now.timestamp())
    revision = 0
    files = {}

    def offer(identity, version, target, sequence):
        return {
            "schema": "fvca-firmware-channel-v1", "role": "hypervisor", "channel": "stable",
            "sequence": sequence, "valid_from": stamp - 60, "expires": stamp + 3600,
            "system_uuid": platform["system_uuid"], "fwupd_version": "2.1.10",
            "offer": {
                "device": identity, "remote": "lvfs", "epoch": 3, "from": version, "to": target,
                "archive": {"sha256": digest(archive), "bytes": len(archive)}, "payload_sha256": "1" * 64,
                "catalog": deepcopy(catalog),
                "qualification": {
                    "distribution_evidence_sha256": "2" * 64, "vendor_authentication": "device-signature",
                    "vendor_evidence_sha256": "3" * 64, "transition_evidence_sha256": "4" * 64,
                    "reboot_policy_sha256": "5" * 64, "recovery_evidence_sha256": "6" * 64,
                },
            },
        }

    def snapshot(document, serial=None):
        document = document["offer"]
        current = observed_device(document["device"], document["from"], serial)
        available = deepcopy(current)
        available["Releases"] = [
            {"Version": document["to"]["text"], "RemoteId": document["remote"], "Protocol": current["Protocols"][0],
             "Checksum": [document["archive"]["sha256"]], "Flags": ["trusted-metadata", "is-upgrade"]},
        ]
        capsule = document["device"]["component"] != "nvme"
        return {
            "schema": "fvca-firmware-observation-v2", "observed_at": stamp, "platform": deepcopy(platform),
            "fwupd_version": "2.1.10", "devices": {"Devices": [current]}, "upgrades": {"Devices": [available]},
            "esrt": [{"guid": document["device"]["guid"], "fw_type": 1,
                      "fw_version": document["from"]["raw"], "lowest_supported_fw_version": document["from"]["raw"],
                      "capsule_flags": 0x50000, "last_attempt_version": document["from"]["raw"],
                      "last_attempt_status": 0}] if capsule else [],
        }

    root_keys = intake["new_keys"]()

    def publish(document, signer=qualified):
        nonlocal revision
        revision += 1
        version = output / f"tuf-{revision}"
        version.mkdir()
        pointer = version / "fvca-firmware-stable.json"
        proof = pointer.with_suffix(".sig")
        intake["write_json"](pointer, document)
        proof.write_bytes(bytes.fromhex(signer.sign(pointer.read_bytes()).signature))
        sources = {pointer.name: pointer, proof.name: proof, cabinet.name: cabinet, **catalog_targets}
        targets = {}
        for name, path in sources.items():
            reference = TargetFile.from_file(name, str(path), ["sha256"])
            published = depot / "targets" / f"{reference.hashes['sha256']}.{name}"
            published.write_bytes(path.read_bytes())
            files[name] = published
            targets[name] = reference
        intake["publish"](version, (1, revision), root_keys, now, targets)
        if not trusted.exists():
            shutil.copyfile(version / "metadata/1.root.json", trusted)
        shutil.copytree(version / "metadata", depot / "metadata", dirs_exist_ok=True)

    initial = offer(bios, {"text": "1.42", "raw": 65578}, {"text": "1.51", "raw": 65587}, 1)
    next_nvme = offer(nvme, {"text": "AFDA4103", "raw": None}, {"text": "FIXTURE-NEXT", "raw": None}, 2)
    publish(initial)
    policy = {
        "schema": "fvca-firmware-policy-v1", "role": "hypervisor", "revision": 1,
        "valid_from": stamp - 60, "expires": stamp + 3600, "channel": "stable", "platform": platform,
        "fwupd_version": "2.1.10", "tuf_root_sha256": intake["sha256"](trusted),
        "depot_config_sha256": intake["sha256"](config), "qualification_key_ed25519": qualified.public_key.keyval["public"],
        "max_archive_bytes": 4096, "allowed_devices": [bios, nvme], "allowed_remotes": ["lvfs"], "minimum_epoch": 3,
    }

    def run(name, observed, want=None, settings=policy, directory=state, *, disposition="staged"):
        intake["write_json"](observation, observed)
        intake["write_json"](policy_path, settings)
        signature.write_bytes(bytes.fromhex(owner.sign(policy_path.read_bytes()).signature))
        result = subprocess.run([client, "--stage-host-firmware", trusted, config, directory,
                                 policy_path, signature, key, observation], capture_output=True, text=True,
                                timeout=25, check=False)
        (output / f"{name}.log").write_text(result.stdout + result.stderr)
        if want:
            assert result.returncode != 0 and want in result.stderr, (name, result)
        else:
            assert result.returncode == 0, (name, result)
            status = json.loads(result.stdout)
            assert status["disposition"] == disposition and stamp <= status["last_refresh"] < status["fresh_until"]
            if disposition == "staged":
                assert status["archive_sha256"] == digest(archive)
                assert "verified_payload_sha256" not in status
                assert "capsule_delivery" not in status
                stage = Path(status["staged"])
                assert {path.name for path in stage.iterdir()} == {"firmware.cab", "offer.json", "offer.sig"}
                assert (stage / "firmware.cab").read_bytes() == archive
                assert list((directory / "staged").iterdir()) == [stage]
            else:
                assert "staged" not in status and not any((directory / "staged").iterdir())
        print(f"{name} passed")

    run("capsule-staged", snapshot(initial))
    run("exact-retry", snapshot(initial))
    catalog_state = output / "tampered-catalog-state"
    catalog_state.mkdir(mode=0o700)
    metadata = next(name for name in catalog_targets if name.endswith(".bin"))
    files[metadata].write_bytes(b"x" * catalog["metadata"]["bytes"])
    run("tampered-catalog-bytes", snapshot(initial), "Hash mismatch", directory=catalog_state)
    assert not any((catalog_state / "staged").iterdir())
    publish(initial)
    wrong_catalog = deepcopy(initial)
    wrong_catalog["offer"]["catalog"]["signature"]["bytes"] += 1
    publish(wrong_catalog)
    length_state = output / "wrong-length-state"
    length_state.mkdir(mode=0o700)
    run("wrong-catalog-length", snapshot(initial), "firmware catalog target length", directory=length_state)
    publish(initial)
    bad = snapshot(initial)
    bad["esrt"][0]["fw_version"] += 1
    run("wrong-esrt-version", bad, "ESRT does not match")
    bad = snapshot(initial)
    bad["observed_at"] -= 301
    run("stale-observation", bad, "observation is stale")
    bad = snapshot(initial)
    bad["devices"]["Devices"][0]["Problems"] = ["firmware-locked"]
    run("inhibited-device", bad, "device is inhibited")
    bad = snapshot(initial)
    bad["upgrades"]["Devices"][0]["Releases"][0]["Flags"] = ["trusted-metadata"]
    run("not-an-upgrade", bad, "trusted eligible upgrade")
    bad = snapshot(initial)
    bad["upgrades"]["Devices"][0]["Releases"][0]["Flags"].append("blocked-approval")
    run("blocked-upgrade", bad, "trusted eligible upgrade")
    run("guest-policy", snapshot(initial), "standing Host firmware policy", settings=dict(policy, role="service-guest"))
    publish(next_nvme)
    nvme_observation = snapshot(next_nvme, "fixture-NVMe-A")
    duplicate = deepcopy(nvme_observation["devices"]["Devices"][0])
    duplicate.update(DeviceId="8" * 40, Serial="fixture-NVMe-B")
    nvme_observation["devices"]["Devices"].append(duplicate)
    run("two-identical-models", nvme_observation)
    interrupted = state / "staged/.firmware-interrupted"
    interrupted.mkdir(mode=0o700)
    (interrupted / "firmware.cab").write_bytes(b"incomplete")
    run("retire-interrupted-staging", nvme_observation)
    bad = snapshot(next_nvme, "fixture-NVMe-A")
    bad["devices"]["Devices"][0]["Flags"].append("wildcard-install")
    run("multi-device-installation", bad, "device is inhibited")
    wrong = snapshot(next_nvme, "fixture-NVMe-B")
    run("same-guid-different-instance", wrong, "qualified physical instance")
    wrong = snapshot(next_nvme, "fixture-NVMe-A")
    wrong["devices"]["Devices"].append(deepcopy(wrong["devices"]["Devices"][0]))
    run("ambiguous-instance", wrong, "observation is ambiguous")
    wrong = snapshot(next_nvme, "fixture-NVMe-A")
    wrong["upgrades"]["Devices"][0]["Releases"][0]["Checksum"] = ["f" * 64]
    run("remote-archive-mismatch", wrong, "exact qualified upgrade")
    publish(initial)
    run("replayed-offer-on-new-tuf-metadata", snapshot(initial), "rollback or equivocation")
    publish(dict(next_nvme, sequence=3), owner)
    run("tuf-and-owner-cannot-replace-qualification", nvme_observation, "independent firmware qualification")
    withdrawal = dict(next_nvme, sequence=3, offer=None)
    unauthorized = dict(withdrawal)
    del unauthorized["offer"]
    publish(unauthorized)
    run("implicit-withdrawal-rejected", nvme_observation, "missing field")
    assert len(list((state / "staged").iterdir())) == 1
    publish(withdrawal)
    run("signed-withdrawal-retires-cabinet", nvme_observation, disposition="no-offer")
    publish(dict(next_nvme, sequence=3))
    run("withdrawal-cannot-be-replayed-over", nvme_observation, "rollback or equivocation")
    publish(dict(next_nvme, sequence=3))
    files[cabinet.name].write_bytes(b"x" * len(archive))
    fresh = output / "tampered-archive-state"
    fresh.mkdir(mode=0o700)
    run("tampered-cabinet", nvme_observation, "Hash mismatch", directory=fresh)
    assert list((fresh / "staged").iterdir()) == []


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("client", "output"):
        parser.add_argument(f"--{option}", required=True, type=lambda value: Path(value).resolve())
    args = parser.parse_args()
    qualify(args.client, args.output)
