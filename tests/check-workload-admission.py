#!/usr/bin/env python3
"""Exercise Guest authorization bindings with independent temporary signers."""

import base64
from hashlib import sha256
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


BINARY = Path(os.environ.get("FVCA_WORKLOAD_ADMISSION", "workload-admission/target/debug/fvca-workload-admission")).absolute()
REVOCATION_ID = "126c779a-0eec-49e8-8671-b9fd37115393"
TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
assemble_image = runpy.run_path(str(TOOLS / "authorize-workload.py"))["assemble_image"]


def digest(content):
    return "sha256:" + sha256(content).hexdigest()


def write(path, record):
    path.write_text(json.dumps(record), encoding="utf-8")
    return digest(path.read_bytes())


def openssl(*args):
    return subprocess.run(["openssl", *args], check=True, capture_output=True).stdout


def sign(path, signer, *flags):
    openssl("cms", "-sign", "-binary", "-nocerts", "-noattr", "-outform", "DER", "-in", path,
            "-signer", signer.with_suffix(".crt"), "-inkey", signer.with_suffix(".key"),
            "-out", path.with_suffix(".p7s"), *flags)


class Admission(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tree = tempfile.TemporaryDirectory(prefix="fvca-admission-")
        cls.addClassCleanup(tree.cleanup)
        root = Path(tree.name)
        cls.deploy = root / "deployment"
        cls.workload = root / "workload"
        for signer in (cls.deploy, cls.workload):
            openssl("req", "-new", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-noenc", "-days", "1", "-subj", f"/CN={signer.name}",
                    "-keyout", signer.with_suffix(".key"), "-out", signer.with_suffix(".crt"))

        cls.fixture = root / "fixture"
        cls.fixture.mkdir(mode=0o700)
        cls.scope = {
            "guest": "guest-test", "service": "test", "source_policy": digest(b"policy"),
            "minimum_epoch": 2, "revoked": [],
        }
        cls.launch = {
            "entrypoint": ["/usr/bin/test"], "command": ["--config", "/etc/test/config.json"],
            "environment": ["CONFIG=yes"], "working_directory": "/var/lib/test", "image_user": "test",
            "uid": 2000, "gid": 2000, "stop_signal": "SIGTERM", "healthcheck": None,
            "volumes": ["/etc/test", "/var/lib/test"],
        }
        cls.deployment = {
            "schema": "fvca-workload-deployment-v1", "role": "service-guest", "guest": "guest-test",
            "service": "test", "source_index": digest(b"index"), "manifest": digest(b"manifest"),
            "launch": write(cls.fixture / "launch.json", cls.launch), "provenance": "PUBLISHER_VERIFIED",
            "network": "none", "valid_from": int(time.time()) - 60, "expires": int(time.time()) + 3600,
            "security_epoch": 2, "revocation_id": REVOCATION_ID,
            "limits": {"memory_bytes": 32 * 1024**2, "cpu_percent": 100, "pids": 128},
            "id_map": {"uid_base": 100000, "gid_base": 100000, "size": 65536},
        }
        root_hash = sha256(b"verity root").hexdigest()
        parts = root / "partitions"
        parts.mkdir()
        (parts / "root.erofs").write_bytes(bytes(4096))
        (parts / "verity.hash").write_bytes(bytes(4096))
        (parts / "root.hash").write_text(root_hash, encoding="ascii")
        sign(parts / "root.hash", cls.workload)
        workload_fingerprint = digest(openssl("x509", "-in", cls.workload.with_suffix(".crt"), "-outform", "DER"))
        seal = json.dumps({"rootHash": root_hash, "certificateFingerprint": workload_fingerprint.removeprefix("sha256:"),
                           "signature": base64.b64encode((parts / "root.p7s").read_bytes()).decode("ascii")})
        assemble_image(cls.fixture / "workload.raw", parts, root_hash, seal.encode("ascii"))
        cls.artifact = (cls.fixture / "workload.raw").read_bytes()
        cls.derivation = {
            "schema": "fvca-workload-derivation-v1", "service": "test", "source_policy": cls.scope["source_policy"],
            "worker_image": digest(b"worker"),
            "provenance": "PUBLISHER_VERIFIED", "source": {
                "repository": "registry.example/test", "index": cls.deployment["source_index"],
                "certificate_identity": "issuer-specific identity", "certificate_issuer": "https://issuer.example",
            }, "platform": {"os": "linux", "architecture": "amd64"}, "manifest": {
                "digest": cls.deployment["manifest"], "size": 1,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
            }, "launch": cls.deployment["launch"], "verity_root_hash": root_hash,
            "root": {"digest": digest(bytes(4096)), "size": 4096},
            "verity_tree": {"digest": digest(bytes(4096)), "size": 4096},
            "config": {}, "layers": [], "converter": {}, "transforms": {},
        }
        cls.authorization = {
            "schema": "fvca-workload-authorization-v1",
            "deployment": write(cls.fixture / "deployment.json", cls.deployment),
            "derivation": write(cls.fixture / "derivation.json", cls.derivation),
            "publisher_proof": write(cls.fixture / "publisher-proof.json", []),
            "deployment_certificate": digest(openssl("x509", "-in", cls.deploy.with_suffix(".crt"), "-outform", "DER")),
            "workload_certificate": workload_fingerprint,
            "artifact": {"size": len(cls.artifact), "digest": digest(cls.artifact)}, "verity_root_hash": root_hash,
        }
        write(cls.fixture / "authorization.json", cls.authorization)
        sign(cls.fixture / "deployment.json", cls.deploy)
        sign(cls.fixture / "authorization.json", cls.workload)

    def setUp(self):
        scratch = tempfile.TemporaryDirectory(prefix="fvca-admission-check-")
        self.addCleanup(scratch.cleanup)
        self.policy = Path(scratch.name) / "policy.json"
        self.bundle = Path(scratch.name) / "bundle"
        shutil.copytree(self.fixture, self.bundle)
        write(self.policy, self.scope)

    def run_check(self, expected=None, workload_signer=None):
        result = subprocess.run([BINARY, self.policy, self.deploy.with_suffix(".crt"),
                                 (workload_signer or self.workload).with_suffix(".crt"), self.bundle],
                                check=False, capture_output=True, text=True)
        if expected is None:
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("FVCA_WORKLOAD_BYTES_VERIFIED", result.stdout)
        else:
            self.assertEqual(result.returncode, 1, result.stdout)
            self.assertIn(expected, result.stderr)

    def test_authorized_bytes(self):
        self.run_check()

    def test_wrong_signer(self):
        sign(self.bundle / "authorization.json", self.deploy)
        self.run_check("workload verification failed")

    def test_shared_signer_key(self):
        self.run_check("share a signer key", workload_signer=self.deploy)

    def test_changed_artifact(self):
        (self.bundle / "workload.raw").write_bytes(b"X" + self.artifact[1:])
        self.run_check("does not match the signed bytes")

    def authorize_disk(self, content):
        (self.bundle / "workload.raw").write_bytes(content)
        path = self.bundle / "authorization.json"
        write(path, dict(self.authorization, artifact={"size": len(content), "digest": digest(content)}))
        sign(path, self.workload)

    def test_authorized_disk_with_invalid_gpt(self):
        content = bytearray(self.artifact)
        content[512] = 0
        self.authorize_disk(content)
        self.run_check("GPT")

    def test_authorized_disk_with_wrong_root_bytes(self):
        content = bytearray(self.artifact)
        content[1024 * 1024] = 1
        self.authorize_disk(content)
        self.run_check("does not match its signed derivation digest")

    def test_authorized_disk_with_wrong_root_seal(self):
        previous = self.authorization["verity_root_hash"].encode("ascii")
        changed = self.artifact.replace(previous, b"0" * len(previous))
        self.assertNotEqual(changed, self.artifact)
        self.authorize_disk(changed)
        self.run_check("verity signature does not bind")

    def test_symlinked_artifact(self):
        path = self.bundle / "workload.raw"
        path.unlink()
        path.symlink_to(self.fixture / "workload.raw")
        self.run_check("workload verification failed")

    def test_changed_launch(self):
        write(self.bundle / "launch.json", dict(self.launch, entrypoint=["/usr/bin/false"]))
        self.run_check("launch.json does not match")

    def test_changed_provenance_evidence(self):
        write(self.bundle / "publisher-proof.json", ["replace"])
        self.run_check("publisher-proof.json does not match")

    def test_revoked(self):
        write(self.policy, dict(self.scope, revoked=[REVOCATION_ID]))
        self.run_check("freshness policy")

    def test_stale_security_epoch(self):
        write(self.policy, dict(self.scope, minimum_epoch=3))
        self.run_check("freshness policy")

    def test_expired_deployment(self):
        path = self.bundle / "deployment.json"
        write(path, dict(self.deployment, expires=int(time.time()) - 1))
        sign(path, self.deploy)
        self.run_check("validity period")

    def test_wrong_guest(self):
        write(self.policy, dict(self.scope, guest="other-guest"))
        self.run_check("trusted scope")

    def test_different_signed_deployment(self):
        path = self.bundle / "deployment.json"
        write(path, dict(self.deployment, security_epoch=3))
        sign(path, self.deploy)
        self.run_check("does not bind these signer pins and deployment")

    def test_signed_duplicate_fields(self):
        path = self.bundle / "deployment.json"
        path.write_text(path.read_text()[:-1] + ',"security_epoch":2}', encoding="utf-8")
        sign(path, self.deploy)
        self.run_check("duplicate field")

    def test_different_attached_content(self):
        path = self.bundle / "deployment.json"
        original = path.read_bytes()
        write(path, dict(self.deployment, security_epoch=3))
        sign(path, self.deploy, "-nodetach")
        path.write_bytes(original)
        self.run_check("workload verification failed")


if __name__ == "__main__":
    unittest.main()
