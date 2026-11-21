#!/usr/bin/env python3
"""Qualify the OpenTofu handoff using signed Hypervisor UKIs and real GPT slots."""

import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from uuid import uuid4


TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import hypervisor_gpt
from guest_boot_bundle import SERVICE_GUEST_ID


HOST = "367f5cbc-c46a-437d-af72-5d96d805d234"
POLICY = "a" * 64
ROOT = "b" * 64
RUNTIME = "c" * 64
GUEST = "d" * 64
SECTOR = 4096
ESP = 272 * 1024**2
SCRIPT = TOOLS / "authorize-guest-configuration.py"


def run(*command, **kwargs):
    return subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs).stdout


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write(path, document):
    path.write_text(json.dumps(document) + "\n", encoding="utf-8")
    return path


def configuration(revision, vcpus, memory):
    body = (f"FVCA-SERVICE-GUEST-VM-2\nguest={SERVICE_GUEST_ID}\nrevision={revision}\n"
            f"vcpus={vcpus}\nmemory_mib={memory}\n").encode("ascii")
    return {"revision": revision, "sha256": digest(body), "vcpus": vcpus, "memory_mib": memory}


def operation_id(previous, after):
    return digest((f"FVCA-GUEST-CONFIGURATION-INTENT-1\nhost={HOST}\nguest={SERVICE_GUEST_ID}\n"
                   f"previous={previous}\nnext={after['revision']},{after['sha256']}\n").encode("ascii"))


class HandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(cls.enterClassContext(tempfile.TemporaryDirectory(prefix="fvca-guest-config-test-")))
        cls.authority, cls.trial_key, cls.other = (cls.root / f"{name}.key" for name in ("config", "trial", "other"))
        for key in (cls.authority, cls.trial_key, cls.other):
            run("openssl", "genpkey", "-algorithm", "Ed25519", "-out", key)
            run("openssl", "pkey", "-in", key, "-pubout", "-out", key.with_suffix(".public"))
        cls.boot_key, cls.certificate = cls.root / "boot.key", cls.root / "boot.crt"
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-noenc", "-days", "1", "-subj", "/CN=FVCA lab boot/",
            "-keyout", cls.boot_key, "-out", cls.certificate)
        cls.enrollment = {"schema": "fvca-hypervisor-management-v1", "host": HOST,
                          "address": "127.0.0.1:8443", "gateway_uid": 62000, "gateway_gid": 62000,
                          "tls_certificate_sha256": "e" * 64, "operator_public_key": "f" * 64,
                          "apply_operator_public_key": "9" * 64}
        cls.enrolled = write(cls.root / "management.json", cls.enrollment)
        cls.proposed = configuration(1, 3, 2560)
        cls.outputs = {"active_configuration": {"revision": None, "sha256": None, "vcpus": 2, "memory_mib": 2048},
                       "planned_configuration": {**cls.proposed, "host_id": HOST, "guest_id": SERVICE_GUEST_ID,
                                                 "activation": "host-trial"},
                       "configuration_operation": {"id": operation_id("default", cls.proposed),
                                                   "state": "pending-activation", "host_trial": False}}
        cls.transaction = str(uuid4())
        cls.stable = cls.slot("stable", None)
        cls.candidate = cls.slot("candidate", cls.proposed)
        cls.other_candidate = cls.slot("other-config", configuration(1, 4, 3072))

    @classmethod
    def slot(cls, name, selected):
        slot_dir = cls.root / name
        slot_dir.mkdir()
        slot_id = uuid4()
        ids = hypervisor_gpt.partition_ids(slot_id)
        keys = [run("openssl", "pkey", "-in", key, "-pubout", "-outform", "DER")[-32:].hex()
                for key in (cls.authority, cls.trial_key)]
        args = [f"roothash={ROOT}", f"fvca.hypervisor_epoch={1 if selected is None else 2},{POLICY}",
                f"fvca.management={digest(cls.enrolled.read_bytes())}", f"fvca.guest_config_key={keys[0]}",
                f"fvca.trial_key={keys[1]}"]
        if selected is not None:
            args += [f"fvca.hypervisor_trial={cls.transaction}", f"fvca.guest_config={selected['revision']},{selected['sha256']}"]
        linux, uki = slot_dir / "linux", slot_dir / "boot.efi"
        linux.write_bytes(b"fixture kernel section for signature checks")
        run("ukify", "build", "--config=/dev/null", f"--linux={linux}", "--uname=fvca-test", "--no-sign-kernel",
            f"--cmdline={' '.join(args)}", f"--secureboot-private-key={cls.boot_key}",
            f"--secureboot-certificate={cls.certificate}", f"--output={uki}")
        esp = slot_dir / "esp.raw"
        run("mkfs.fat", "-C", "-F", "32", "-S", str(SECTOR), "-s", "1", esp, str(ESP // 1024))
        run("mmd", "-i", esp, "::/EFI", "::/EFI/BOOT")
        run("mcopy", "-i", esp, uki, "::/EFI/BOOT/BOOTX64.EFI")
        image = slot_dir / "slot.raw"
        start = 256
        with image.open("xb") as stream:
            stream.truncate(ESP + 4 * 1024**2)
        table = ["label: gpt", f"label-id: {slot_id}", "unit: sectors"]
        for name, kind in hypervisor_gpt.PARTITIONS.items():
            count = ESP // SECTOR if name == "esp" else 1
            table.append(f"start={start}, size={count}, type={kind}, uuid={ids[name]}")
            start += count
        run("sfdisk", "--sector-size", str(SECTOR), "--no-reread", "--no-tell-kernel", "--quiet", image,
            input=("\n".join(table) + "\n").encode("ascii"))
        run("dd", f"if={esp}", f"of={image}", f"bs={SECTOR}", "seek=256", "conv=sparse,notrunc", "status=none")
        with esp.open("rb") as stream:
            esp_hash = hashlib.file_digest(stream, "sha256").hexdigest()
        result = {"ids": ids, "disk": image, "esp_sha256": esp_hash, "loader": uki.read_bytes()}
        esp.unlink()
        linux.unlink()
        uki.unlink()
        return result

    def setUp(self):
        self.work = Path(self.enterContext(tempfile.TemporaryDirectory(dir=self.root)))
        self.input = write(self.work / "outputs.json", self.outputs)
        self.destination = self.work / "approval"

    def approval(self, candidate, *, expired=False):
        now = int(time.time())
        prior, expiry = now - 80, now - 1 if expired else now + 3600
        context = (f"FVCA-HYPERVISOR-STANDING-TRIAL-2\nnot_before={prior}\nexpires={expiry}\n"
                   f"stable_epoch=1\ncandidate_epoch=2\nepoch_policy_sha256={POLICY}\n"
                   f"stable_core={ROOT}\nstable_runtime={RUNTIME}\nstable_guest_bundle={GUEST}\n"
                   f"candidate_uki_sha256={digest(candidate['loader'])}\ncandidate_uki_bytes={len(candidate['loader'])}\n"
                   + "".join(f"candidate_{name}_devices={candidate['ids'][name]},{candidate['ids'][f'{name}_verity']}\n"
                             for name in ("core", "runtime", "guest")))
        trial = (f"FVCA-HYPERVISOR-TRIAL-2\ntransaction={self.transaction}\nstable=0001,{self.stable['ids']['esp']}\n"
                 f"candidate=0002,{candidate['ids']['esp']}\ncandidate_esp_sha256={candidate['esp_sha256']}\n"
                 f"candidate_esp_bytes={ESP}\ncandidate_core={ROOT}\ncandidate_runtime={RUNTIME}\nguest_bundle={GUEST}\n")
        body = self.work / "trial.txt"
        body.write_text(context + trial, encoding="ascii")
        packet = self.work / "trial.bin"
        packet.write_bytes(run("openssl", "pkeyutl", "-sign", "-rawin", "-inkey", self.trial_key, "-in", body)
                           + body.read_bytes())
        return packet

    def prepare(self):
        return self.command("prepare")

    def command(self, mode, *options, enrollment=None):
        return subprocess.run([sys.executable, "-B", "-W", "error", SCRIPT, mode, "--outputs", self.input,
                               "--enrollment", enrollment or self.enrolled, "--output", self.destination, *options],
                              capture_output=True, text=True, check=False)

    def authorize(self, candidate=None, packet=None, signer=None, *, enrollment=None):
        candidate = candidate or self.candidate
        packet = packet or self.approval(candidate)
        return self.command("authorize", "--stable", self.stable["disk"], "--candidate", candidate["disk"],
                            "--boot-certificate", self.certificate, "--trial", packet,
                            "--configuration-key", signer or self.authority, enrollment=enrollment)

    def refused(self, result, phrase):
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(phrase, result.stderr)
        self.assertFalse(self.destination.exists())

    def test_prepares_exact_composer_settings(self):
        result = self.prepare()
        self.assertEqual(result.returncode, 0, result.stderr)
        original = self.destination.read_bytes()
        composer = runpy.run_path(str(TOOLS / "compose-hypervisor.py"))
        _, arguments = composer["guest_vm_settings"](self.destination)
        self.assertEqual(arguments, (f"fvca.guest_config=1,{self.proposed['sha256']}",))
        self.assertEqual(self.destination.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.prepare().returncode, 1)
        self.assertEqual(self.destination.read_bytes(), original)

    def test_exact_standing_approval_signature(self):
        packet = self.approval(self.candidate)
        result = self.authorize(packet=packet)
        self.assertEqual(result.returncode, 0, result.stderr)
        approval = self.destination.read_bytes()
        self.assertEqual(approval[64:], (
            f"FVCA-GUEST-CONFIGURATION-CHANGE-1\nguest={SERVICE_GUEST_ID}\ntrial_sha256={digest(packet.read_bytes())}\n"
            f"previous=default\nnext=1,{self.proposed['sha256']}\n"
        ).encode("ascii"))
        body, signature = self.work / "body", self.work / "signature"
        body.write_bytes(approval[64:])
        signature.write_bytes(approval[:64])
        run("openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", self.authority.with_suffix(".public"),
            "-in", body, "-sigfile", signature)
        if evidence := os.environ.get("FVCA_GUEST_CONFIG_TEST_EVIDENCE"):
            evidence = Path(evidence)
            for name, content in (("approval.bin", approval), ("trial.sha256", digest(packet.read_bytes()).encode())):
                (evidence / name).write_bytes(content)
            shutil.copyfile(self.authority.with_suffix(".public"), evidence / "configuration.public.pem")
            shutil.copyfile(self.input, evidence / "outputs.json")
            shutil.copyfile(self.enrolled, evidence / "management.json")

    def test_refuses_inconsistent_manager_outputs(self):
        for group, field, value, expected in (
            ("configuration_operation", "id", "0" * 64, "operation ID differs"),
            ("configuration_operation", "state", "active", "expected a pending Host trial"),
            ("planned_configuration", "vcpus", True, "resources exceed"),
            ("planned_configuration", "sha256", "0" * 64, "configuration digest differs"),
            ("planned_configuration", "guest_id", str(uuid4()), "Host or Guest identity"),
        ):
            with self.subTest(group=group, field=field):
                outputs = copy.deepcopy(self.outputs)
                outputs[group][field] = value
                write(self.input, outputs)
                self.refused(self.prepare(), expected)

    def test_refuses_stale_stable_binding(self):
        outputs = copy.deepcopy(self.outputs)
        active, planned = configuration(1, 2, 2048), configuration(2, 3, 2560)
        outputs["active_configuration"] = active
        outputs["planned_configuration"].update(planned)
        outputs["configuration_operation"]["id"] = operation_id(f"1,{active['sha256']}", planned)
        write(self.input, outputs)
        self.refused(self.authorize(), "different fvca.guest_config binding")

    def test_refuses_another_trial_candidate(self):
        self.refused(self.authorize(candidate=self.other_candidate, packet=self.approval(self.candidate)),
                     "candidate disk layout differs")
        self.refused(self.authorize(candidate=self.other_candidate), "different fvca.guest_config binding")

    def test_refuses_the_wrong_authority_or_enrollment(self):
        self.refused(self.authorize(signer=self.other), "different fvca.guest_config_key binding")
        enrollment = write(self.work / "other.json", {**self.enrollment, "address": "127.0.0.1:8455"})
        self.refused(self.authorize(enrollment=enrollment), "different fvca.management binding")
        enroll = {key: value for key, value in self.enrollment.items() if key != "apply_operator_public_key"}
        enrollment = write(self.work / "read-only.json", enroll)
        self.refused(self.command("prepare", enrollment=enrollment), "lacks a configuration submitter key")

    def test_refuses_an_expired_or_tampered_trial(self):
        self.refused(self.authorize(packet=self.approval(self.candidate, expired=True)), "signed validity interval")
        packet = self.approval(self.candidate)
        raw = packet.read_bytes()
        packet.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
        self.refused(self.authorize(packet=packet), "returned non-zero exit status")

    def test_standing_promotion_uses_the_same_trial_and_slot(self):
        trial = self.approval(self.candidate)
        active = write(self.work / "active.json", {"role": "hypervisor", "slot": "a", "epoch": 1,
                                                   "sequence": 1, "manifest_sha256": "e" * 64})
        image = self.candidate["disk"]
        with image.open("rb") as stream:
            boot = {"bytes": image.stat().st_size, "sha256": hashlib.file_digest(stream, "sha256").hexdigest()}
        manifest = write(self.work / "candidate.json", {"schema": "fvca-os-release-v1", "epoch": 2,
                                                         "composition": {"role": "hypervisor", "boot": boot}})
        run(sys.executable, "-B", "-W", "error", TOOLS / "sign-hypervisor-promotion.py",
            "--trial", trial, "--candidate", image, "--standing-active", active, "--candidate-manifest", manifest,
            "--candidate-sequence", "2", "--trial-key", self.trial_key.with_suffix(".public"),
            "--sign-key", self.other, "--output", self.destination)
        promoted = self.destination.read_bytes()[64:]
        self.assertTrue(promoted.startswith(b"FVCA-HYPERVISOR-STANDING-PROMOTION-2\n"))
        self.assertTrue(promoted.endswith(trial.read_bytes()[64:]))


if __name__ == "__main__":
    unittest.main()
