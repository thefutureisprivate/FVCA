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
    transition_targets = {}
    operational_targets = {}
    evidence_fields = {
        "distribution": "distribution_evidence_sha256",
        "vendor": "vendor_evidence_sha256",
        "reboot-policy": "reboot_policy_sha256",
        "recovery": "recovery_evidence_sha256",
    }

    def transition_for(document):
        selected = document["offer"]
        before = {
            "esp": "d0d2fd6b-ee28-4034-a022-b3da25744690",
            "core": "7" * 64, "runtime": "8" * 64, "epoch": 10,
            "epoch_policy_sha256": "9" * 64,
            "tpm_floor": 9, "pcr7_sha256": "c" * 64,
            "filesystem": "dfc379cc-7f43-4c4d-8b3b-e9b34c112712",
            "storage_policy_sha256": "a" * 64,
        }
        return {
            "schema": "fvca-firmware-boot-transition-v3",
            "system_uuid": document["system_uuid"], "fwupd_version": document["fwupd_version"],
            "device": selected["device"], "from": selected["from"], "to": selected["to"],
            "archive_sha256": selected["archive"]["sha256"], "payload_sha256": selected["payload_sha256"],
            "qualified_at": stamp - 600,
            "key_release": "preserve-enrollment", "before": before, "after": dict(before),
        }

    def bind_transition(document, evidence):
        body = json.dumps(evidence, sort_keys=True).encode() + b"\n"
        checksum = digest(body)
        path = output / f"fvca-firmware-transition-{checksum}.json"
        path.write_bytes(body)
        transition_targets[checksum] = path
        document["offer"]["qualification"]["transition_evidence_sha256"] = checksum

    def bind_operational(document, kind, evidence, transition=None):
        qualification = document["offer"]["qualification"]
        body = json.dumps({
            "schema": f"fvca-firmware-{kind}-v1",
            "transition_sha256": transition or qualification["transition_evidence_sha256"],
            "evidence": evidence,
        }, sort_keys=True).encode() + b"\n"
        checksum = digest(body)
        path = output / f"fvca-firmware-{kind}-{checksum}.json"
        path.write_bytes(body)
        operational_targets[checksum] = path
        qualification[evidence_fields[kind]] = checksum

    def offer(identity, version, target, sequence):
        document = {
            "schema": "fvca-firmware-channel-v1", "role": "hypervisor", "channel": "stable",
            "sequence": sequence, "valid_from": stamp - 60, "expires": stamp + 3600,
            "system_uuid": platform["system_uuid"], "fwupd_version": "2.1.10",
            "offer": {
                "device": identity, "remote": "lvfs", "epoch": 3, "from": version, "to": target,
                "archive": {"sha256": digest(archive), "bytes": len(archive)}, "payload_sha256": "1" * 64,
                "catalog": deepcopy(catalog),
                "qualification": {"vendor_authentication": "device-signature"},
            },
        }
        bind_transition(document, transition_for(document))
        bind_operational(document, "distribution", {
            "remote": "lvfs", "metadata_sha256": catalog["metadata"]["sha256"],
            "signature_sha256": catalog["signature"]["sha256"],
        })
        bind_operational(document, "vendor", {"authentication": "device-signature", "procedure": "Fixture vendor qualification"})
        bind_operational(document, "reboot-policy", {
            "urgency": "routine",
            "delivery": "offline-nvme" if identity["component"] == "nvme" else "capsule-on-disk",
            "power": "no-additional-requirement", "steps": ["reboot"],
        })
        bind_operational(document, "recovery", {
            "method": "vendor-procedure", "procedure": "Fixture recovery", "qualified_retries": 0,
        })
        return document

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

    def publish(document, signer=qualified, *, transition_source=None):
        nonlocal revision
        revision += 1
        version = output / f"tuf-{revision}"
        version.mkdir()
        pointer = version / "fvca-firmware-stable.json"
        proof = pointer.with_suffix(".sig")
        intake["write_json"](pointer, document)
        proof.write_bytes(bytes.fromhex(signer.sign(pointer.read_bytes()).signature))
        sources = {pointer.name: pointer, proof.name: proof, cabinet.name: cabinet, **catalog_targets}
        if document.get("offer"):
            evidence = document["offer"]["qualification"]["transition_evidence_sha256"]
            path = transition_source or transition_targets.get(evidence)
            if path is not None:
                sources[f"fvca-firmware-transition-{evidence}.json"] = path
            for kind, field in evidence_fields.items():
                evidence = document["offer"]["qualification"][field]
                path = operational_targets.get(evidence)
                if path is not None:
                    sources[f"fvca-firmware-{kind}-{evidence}.json"] = path
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

    def run(name, observed, want=None, settings=policy, directory=state, *, disposition="staged", urgency="routine"):
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
                qualification = status["qualification"]
                assert qualification["qualified_at"] == stamp - 600
                assert qualification["age_seconds"] == qualification["observed_at"] - qualification["qualified_at"] >= 600
                assert "verified_payload_sha256" not in status
                assert "capsule_delivery" not in status
                stage = Path(status["staged"])
                assert {path.name for path in stage.iterdir()} == {
                    "firmware.cab", "offer.json", "offer.sig", "transition.json",
                    "distribution.json", "vendor.json", "reboot-policy.json", "recovery.json",
                }
                assert (stage / "firmware.cab").read_bytes() == archive
                assert digest((stage / "transition.json").read_bytes()) == status["transition_evidence_sha256"]
                assert status["urgency"] == urgency and "operational_preflight" not in status
                assert list((directory / "staged").iterdir()) == [stage]
            else:
                assert "staged" not in status and not any((directory / "staged").iterdir())
        print(f"{name} passed")

    run("capsule-staged", snapshot(initial))
    run("exact-retry", snapshot(initial))
    refreshed = output / "refreshed-channel-state"
    refreshed.mkdir(mode=0o700)
    publish(dict(initial, sequence=2, valid_from=stamp - 30, expires=stamp + 3700))
    run("channel-refresh-preserves-qualification-date", snapshot(initial), directory=refreshed)
    for name, date, message in (
        ("future-qualification", stamp + 600, "qualification is in the future"),
        ("missing-qualification-date", None, "missing field `qualified_at`"),
    ):
        dated = deepcopy(initial)
        evidence = transition_for(dated)
        if date is None:
            del evidence["qualified_at"]
        else:
            evidence["qualified_at"] = date
        bind_transition(dated, evidence)
        isolated = output / (name + "-state")
        isolated.mkdir(mode=0o700)
        publish(dated)
        run(name, snapshot(initial), message, directory=isolated)
        assert not any((isolated / "staged").iterdir())
    publish(initial)
    bad_window = {"timezone": "Europe/Berlin", "start_minute": 240, "end_minute": 240}
    run("invalid-signed-maintenance-window", snapshot(initial), "invalid maintenance window",
        settings=dict(policy, maintenance=bad_window))
    missing_vendor = deepcopy(initial)
    missing_vendor["offer"]["qualification"]["vendor_evidence_sha256"] = "f" * 64
    cases = [("missing-vendor-proof", missing_vendor, "missing or oversized TUF channel target")]
    foreign_vendor = deepcopy(initial)
    bind_operational(foreign_vendor, "vendor",
                     {"authentication": "device-signature", "procedure": "Fixture other transition"}, "f" * 64)
    cases.append(("foreign-vendor-proof", foreign_vendor, "differs from the qualified transition"))
    wrong_vendor = deepcopy(initial)
    bind_operational(wrong_vendor, "vendor", {
        "authentication": "independently-verified-vendor-signature", "procedure": "Fixture weaker evidence",
        "signer_sha256": "a" * 64,
    })
    cases.append(("vendor-authentication-mismatch", wrong_vendor, "invalid qualified vendor authentication evidence"))
    wrong_distribution = deepcopy(initial)
    bind_operational(wrong_distribution, "distribution", {
        "remote": "lvfs", "metadata_sha256": "a" * 64, "signature_sha256": catalog["signature"]["sha256"],
    })
    cases.append(("distribution-catalog-mismatch", wrong_distribution, "differs from the selected catalog"))
    wrong_route = deepcopy(initial)
    bind_operational(wrong_route, "reboot-policy", {
        "urgency": "routine", "delivery": "offline-nvme", "power": "mains-required", "steps": ["reboot"],
    })
    cases.append(("unsupported-device-route", wrong_route, "differs from the selected device protocol"))
    unsafe_recovery = deepcopy(initial)
    bind_operational(unsafe_recovery, "recovery", {
        "method": "physical-repair", "procedure": "Fixture repair only", "qualified_retries": 1,
    })
    cases.append(("physical-repair-cannot-retry", unsafe_recovery, "invalid qualified firmware recovery procedure"))
    for name, modified, reason in cases:
        isolated = output / (name + "-state")
        isolated.mkdir(mode=0o700)
        publish(modified)
        run(name, snapshot(initial), reason, directory=isolated)
        assert not any((isolated / "staged").iterdir())
    security = deepcopy(initial)
    bind_operational(security, "reboot-policy", {
        "urgency": "security", "delivery": "capsule-on-disk", "power": "continuity-required", "steps": ["reboot"],
    })
    security_state = output / "security-state"
    security_state.mkdir(mode=0o700)
    publish(security)
    run("signed-security-urgency", snapshot(initial), directory=security_state, urgency="security")
    publish(initial)
    stored = next((state / "staged").iterdir()) / "transition.json"
    assert stored.stat().st_mode & 0o777 == 0o400
    original = stored.read_bytes()
    stored.unlink()
    stored.write_bytes(b"x" * len(original))
    stored.chmod(0o400)
    run("changed-staged-transition", snapshot(initial), "existing firmware stage does not match")
    stored.unlink()
    stored.write_bytes(original)
    stored.chmod(0o400)
    evidence_state = output / "transition-state"
    evidence_state.mkdir(mode=0o700)
    missing = deepcopy(initial)
    missing["offer"]["qualification"]["transition_evidence_sha256"] = "d" * 64
    publish(missing)
    run("missing-boot-transition", snapshot(initial), "missing or oversized TUF channel target", directory=evidence_state)
    substitute = output / "substitute-transition.json"
    intake["write_json"](substitute, transition_for(next_nvme))
    publish(initial, transition_source=substitute)
    # Use an independent state so the offer checkpoint does not hide a substituted artifact.
    replacement_state = output / "transition-substitution-state"
    replacement_state.mkdir(mode=0o700)
    run("tuf-cannot-substitute-transition", snapshot(initial), "differs from the signed offer", directory=replacement_state)
    wrong = deepcopy(initial)
    changed = transition_for(wrong)
    changed["to"] = {"text": "1.52", "raw": 65588}
    bind_transition(wrong, changed)
    publish(wrong)
    mismatch_state = output / "transition-mismatch-state"
    mismatch_state.mkdir(mode=0o700)
    run("transition-target-mismatch", snapshot(initial), "differs from the qualified release", directory=mismatch_state)
    changed = transition_for(wrong)
    changed["key_release"] = "requires-preparation"
    changed["after"]["epoch"] = changed["before"]["epoch"] - 1
    bind_transition(wrong, changed)
    publish(wrong)
    rollback_state = output / "transition-rollback-state"
    rollback_state.mkdir(mode=0o700)
    run("transition-epoch-rollback", snapshot(initial), "invalid boot or storage policies", directory=rollback_state)
    changed["after"]["epoch"] = changed["before"]["epoch"]
    changed["after"]["tpm_floor"] = changed["before"]["tpm_floor"] - 1
    bind_transition(wrong, changed)
    publish(wrong)
    floor_state = output / "transition-floor-rollback-state"
    floor_state.mkdir(mode=0o700)
    run("transition-floor-rollback", snapshot(initial), "invalid boot or storage policies", directory=floor_state)
    changed = transition_for(wrong)
    changed["after"]["pcr7_sha256"] = "d" * 64
    bind_transition(wrong, changed)
    publish(wrong)
    pcr_state = output / "transition-changed-pcr-state"
    pcr_state.mkdir(mode=0o700)
    run("preservation-with-changed-pcr", snapshot(initial), "under preserved TPM enrollment", directory=pcr_state)
    for unused in (evidence_state, replacement_state, mismatch_state, rollback_state, floor_state, pcr_state):
        assert not any((unused / "staged").iterdir())
    publish(initial)
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
