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
from uuid import uuid4


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


def portable(content):
    return base64.b64encode(content).decode("ascii")


def source_policy(derivation, launch, schema):
    return json.dumps({
        "schema": schema, "service": derivation["service"], **derivation["source"],
        "manifest": derivation["manifest"]["digest"],
        **{field: launch[field] for field in ("uid", "gid", "volumes")},
    }).encode("ascii")


def publisher_evidence(derivation, launch):
    policy = source_policy(derivation, launch, "fvca-oci-source-v1")
    source = derivation["source"]
    return {"provenance": "PUBLISHER_VERIFIED", "policy": portable(policy), "proof": [{"critical": {
        "type": "https://sigstore.dev/cosign/sign/v1", "image": {"docker-manifest-digest": source["index"]},
        "identity": {"docker-reference": f"{source['repository']}@{source['index']}"},
    }}]}


class Admission(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tree = tempfile.TemporaryDirectory(prefix="fvca-admission-")
        cls.addClassCleanup(tree.cleanup)
        root = Path(tree.name)
        cls.deploy = root / "deployment"
        cls.workload = root / "workload"
        cls.permit_authority = root / "permit-authority"
        for signer in (cls.deploy, cls.workload, cls.permit_authority):
            openssl("req", "-new", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-noenc", "-days", "1", "-subj", f"/CN={signer.name}",
                    "-keyout", signer.with_suffix(".key"), "-out", signer.with_suffix(".crt"))

        cls.fixture = root / "fixture"
        cls.fixture.mkdir(mode=0o700)
        cls.scope = {
            "guest": "guest-test", "service": "test",
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
            "schema": "fvca-workload-derivation-v1", "service": "test",
            "worker_image": digest(b"worker"),
            "provenance": "PUBLISHER_VERIFIED", "source": {
                "repository": "registry.example/test", "index": cls.deployment["source_index"],
                "certificate_identity": "https://registry.example/workflow", "certificate_issuer": "https://issuer.example",
            }, "platform": {"os": "linux", "architecture": "amd64"}, "manifest": {
                "digest": cls.deployment["manifest"], "size": 1,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
            }, "launch": cls.deployment["launch"], "verity_root_hash": root_hash,
            "root": {"digest": digest(bytes(4096)), "size": 4096},
            "verity_tree": {"digest": digest(bytes(4096)), "size": 4096},
            "config": {}, "layers": [], "converter": {}, "transforms": {},
        }
        source = publisher_evidence(cls.derivation, cls.launch)
        cls.scope["source_policy"] = digest(base64.b64decode(source["policy"], validate=True))
        cls.derivation["source_policy"] = cls.scope["source_policy"]
        cls.authorization = {
            "schema": "fvca-workload-authorization-v2",
            "deployment": write(cls.fixture / "deployment.json", cls.deployment),
            "derivation": write(cls.fixture / "derivation.json", cls.derivation),
            "source_evidence": write(cls.fixture / "source-evidence.json", source),
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

    def run_check(self, expected=None, workload_signer=None, bundle=None):
        result = subprocess.run([BINARY, self.policy, self.deploy.with_suffix(".crt"),
                                 (workload_signer or self.workload).with_suffix(".crt"), bundle or self.bundle],
                                check=False, capture_output=True, text=True)
        if expected is None:
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("FVCA_WORKLOAD_BYTES_VERIFIED", result.stdout)
        else:
            self.assertEqual(result.returncode, 1, result.stdout)
            self.assertIn(expected, result.stderr)
        return result.stdout

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
        write(self.bundle / "source-evidence.json", ["replace"])
        self.run_check("source-evidence.json does not match")

    def unsigned(self, *, bundle=None, issuer=None, signer=None, request=None):
        bundle = bundle or self.bundle
        issuer = issuer or self.permit_authority
        deployment = json.loads((bundle / "deployment.json").read_bytes())
        derivation = json.loads((bundle / "derivation.json").read_bytes())
        launch = json.loads((bundle / "launch.json").read_bytes())
        certificate = openssl("x509", "-in", issuer.with_suffix(".crt"), "-outform", "DER")
        pin = digest(certificate)
        classification = "UNSIGNED_UPSTREAM_APPROVED"
        deployment["provenance"] = classification
        derivation["provenance"] = classification
        source = {"repository": derivation["source"]["repository"], "index": deployment["source_index"], "permit_authority": pin}
        derivation["source"] = source
        policy = source_policy(derivation, launch, "fvca-oci-explicit-exceptions-v1")
        now = int(time.time())
        acceptance = {
            "schema": "fvca-workload-permit-request-v1", "operator": "reviewer", "role": "workload-unsigned-approver",
            "guest": deployment["guest"], "service": deployment["service"], "repository": source["repository"],
            "source_policy": digest(policy), "source_index": source["index"], "manifest": deployment["manifest"],
            "platform": derivation["platform"], "launch": deployment["launch"],
            "acknowledgment": "I KNOW THIS MIGHT BE INSECURE", "reason": "Reviewed exact fixture",
            "requested_at": now - 20, "expires": now + 90, "revocation_id": str(uuid4()),
            "revocation_action": "block-new-starts",
        } | (request or {})
        absent = {"status": 404, "response": digest(b"confirmed absent")}
        permit = {
            "schema": "fvca-workload-unsigned-permit-v1", "provenance": classification,
            "acknowledgment": acceptance, "request_sha256": digest(b"signed request"),
            "operator_certificate": digest(b"operator cert"), "delegation_sha256": digest(b"signed delegation"),
            "issued_at": now - 10, "expiry_action": "block-new-starts",
            "discovery": {"schema": "fvca-signature-discovery-v1", "repository": source["repository"], "subjects": [
                {"digest": subject, "referrers_api": absent, "referrers_tag": absent, "cosign_signature_tag": absent}
                for subject in (source["index"], deployment["manifest"])
            ]},
        }
        record = bundle.with_name("permit.json")
        derivation["permit"] = write(record, permit)
        sign(record, signer or issuer)
        evidence = {"provenance": classification, "policy": portable(policy), "permit": portable(record.read_bytes()),
                    "authority": portable(certificate), "signature": portable(record.with_suffix(".p7s").read_bytes())}
        auth_hash = self.bind_endpoint(bundle, launch, deployment, derivation, (bundle / "workload.raw").read_bytes(), evidence)
        scope = dict(self.scope, source_policy=digest(policy), unsigned_permit_authority=pin)
        if bundle == self.bundle:
            write(self.policy, scope)
        return scope, acceptance, auth_hash

    def test_unsigned_requires_explicit_enrollment_and_reports_effective_expiry(self):
        scope, permit, _ = self.unsigned()
        output = self.run_check()
        self.assertIn(f"UNSIGNED_UPSTREAM_APPROVED {permit['revocation_id']} {permit['expires']}", output)
        del scope["unsigned_permit_authority"]
        write(self.policy, scope)
        self.run_check("does not enable unsigned permits")

    def test_revoked_unsigned_permit_blocks_admission(self):
        scope, permit, _ = self.unsigned()
        write(self.policy, dict(scope, revoked=[permit["revocation_id"]]))
        self.run_check("unsigned workload permit is revoked")

    def test_expired_unsigned_permit_blocks_admission(self):
        self.unsigned(request={"expires": int(time.time()) - 1})
        self.run_check("unsigned workload permit is outside its validity period")

    def test_unsigned_permit_rejects_other_destination_and_manifest(self):
        for values in ({"guest": "different-guest"}, {"manifest": digest(b"other manifest")}):
            with self.subTest(values=values):
                self.unsigned(request=values)
                self.run_check("does not bind the exact workload and acknowledgment")

    def test_unsigned_permit_requires_its_own_signature_and_key(self):
        self.unsigned(signer=self.workload)
        self.run_check("workload verification failed")
        self.unsigned(issuer=self.workload)
        self.run_check("requires a distinct authority key")

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

    def bind_endpoint(self, path, launch, deployment, derivation, artifact, source=None):
        launch_digest = write(path / "launch.json", launch)
        deploy_path = path / "deployment.json"
        auth_path = path / "authorization.json"
        if source is None:
            source = publisher_evidence(derivation, launch)
        policy_hash = digest(base64.b64decode(source["policy"], validate=True))
        deployment_digest = write(deploy_path, dict(deployment, launch=launch_digest))
        derivation_digest = write(path / "derivation.json", dict(derivation, launch=launch_digest, source_policy=policy_hash))
        (path / "workload.raw").write_bytes(artifact)
        output = write(auth_path, dict(
            self.authorization, deployment=deployment_digest, derivation=derivation_digest,
            artifact={"size": len(artifact), "digest": digest(artifact)},
            verity_root_hash=derivation["verity_root_hash"],
            source_evidence=write(path / "source-evidence.json", source),
        ))
        sign(deploy_path, self.deploy)
        sign(auth_path, self.workload)
        return output

    def prepare_transition(self, *, deployment=None, launch=None, source=None, root=b"R" * 4096):
        health = {
            "Test": ["CMD", "/usr/bin/test-health"], "Interval": 1_000_000_000,
            "Timeout": 1_000_000_000, "StartPeriod": None, "StartInterval": None, "Retries": 1,
        }
        active_launch = dict(self.launch, healthcheck=health)
        active_deployment = dict(self.deployment, security_epoch=3)
        from_authorization = self.bind_endpoint(
            self.bundle, active_launch, active_deployment, self.derivation, self.artifact,
        )
        candidate = self.bundle.with_name("candidate")
        shutil.copytree(self.bundle, candidate)
        index = digest(b"next index")
        manifest = digest(b"next manifest")
        target_deployment = dict(active_deployment, source_index=index, manifest=manifest)
        target_deployment.update(deployment or {})
        target_launch = active_launch | (launch or {})
        target_source = dict(self.derivation["source"], index=index) | (source or {})
        derivation = dict(
            self.derivation, source=target_source,
            manifest=dict(self.derivation["manifest"], digest=manifest),
        )
        parts = candidate.with_name("next-parts")
        parts.mkdir()
        (parts / "root.erofs").write_bytes(root)
        (parts / "verity.hash").write_bytes(bytes(4096))
        verity = sha256(b"next verity root").hexdigest()
        (parts / "root.hash").write_text(verity, encoding="ascii")
        sign(parts / "root.hash", self.workload)
        seal = json.dumps({
            "rootHash": verity,
            "certificateFingerprint": self.authorization["workload_certificate"].removeprefix("sha256:"),
            "signature": base64.b64encode((parts / "root.p7s").read_bytes()).decode("ascii"),
        })
        disk = candidate.with_name("next-workload.raw")
        assemble_image(disk, parts, verity, seal.encode("ascii"))
        artifact = disk.read_bytes()
        derivation.update(verity_root_hash=verity, root={"digest": digest(root), "size": len(root)})
        to_authorization = self.bind_endpoint(candidate, target_launch, target_deployment, derivation, artifact)
        policy = json.loads((candidate / "derivation.json").read_bytes())["source_policy"]
        now = int(time.time())
        return {
            "schema": "fvca-workload-transition-v1", "guest": self.scope["guest"], "service": self.scope["service"],
            "from_authorization": from_authorization, "to_authorization": to_authorization,
            "to_source_policy": policy, "data_compatibility": "bidirectional",
            "valid_from": now - 60, "expires": now + 120,
        }, candidate

    def run_transition(self, record, candidate, expected=None, authority=None, fresh_until=None):
        grant = self.bundle.with_name("transition.json")
        write(grant, record)
        sign(grant, authority or self.deploy)
        result = subprocess.run([
            BINARY, "--verify-transition", self.policy, self.deploy.with_suffix(".crt"),
            self.workload.with_suffix(".crt"), self.bundle, candidate, grant, grant.with_suffix(".p7s"),
        ], check=False, capture_output=True, text=True)
        if expected is None:
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), " ".join([
                "FVCA_WORKLOAD_TRANSITION_VERIFIED", self.scope["service"], record["from_authorization"],
                record["to_authorization"], str(fresh_until or record["expires"]),
            ]))
        else:
            self.assertEqual(result.returncode, 1, result.stdout)
            self.assertIn(expected, result.stderr)
            self.assertNotIn("FVCA_WORKLOAD_TRANSITION_VERIFIED", result.stdout)

    def test_transition_requires_exact_signed_source_and_authorizations(self):
        grant, candidate = self.prepare_transition()
        self.run_transition(grant, candidate)
        self.run_check("derivation does not match", bundle=candidate)
        self.run_transition(dict(grant, from_authorization=digest(b"other active release")), candidate,
                            "authorization differs from the signed transition")
        self.run_transition(dict(grant, to_source_policy=self.scope["source_policy"]), candidate,
                            "derivation does not match")
        self.run_transition(dict(grant, to_authorization=digest(b"other authorization")), candidate,
                            "authorization differs from the signed transition")
        self.run_transition(grant, candidate, "workload verification failed", authority=self.workload)

    def test_transition_rejects_expiry_and_altered_candidate_bytes(self):
        grant, candidate = self.prepare_transition()
        self.run_transition(dict(grant, expires=int(time.time()) - 1), candidate, "outside its validity")
        disk = candidate / "workload.raw"
        disk.write_bytes(b"X" + disk.read_bytes()[1:])
        self.run_transition(grant, candidate, "does not match the signed bytes")

    def test_transition_retains_the_earliest_authorization_expiry(self):
        expires = int(time.time()) + 60
        grant, candidate = self.prepare_transition(deployment={"expires": expires})
        self.run_transition(grant, candidate, fresh_until=expires)

    def test_transition_rejects_an_older_epoch(self):
        grant, candidate = self.prepare_transition(deployment={"security_epoch": 2})
        self.run_transition(grant, candidate, "roll back the active security epoch")

    def test_transition_rejects_changed_persistent_volumes(self):
        grant, candidate = self.prepare_transition(launch={"volumes": ["/var/lib/test"]})
        self.run_transition(grant, candidate, "persistent volume or container identity mapping")

    def test_transition_rejects_privilege_expansion(self):
        larger = dict(self.deployment["limits"], memory_bytes=64 * 1024**2)
        grant, candidate = self.prepare_transition(deployment={"limits": larger})
        self.run_transition(grant, candidate, "network or resource scope")

    def test_transition_rejects_a_different_publisher_repository(self):
        grant, candidate = self.prepare_transition(source={"repository": "registry.example/other"})
        self.run_transition(grant, candidate, "publisher repository or issuer")

    def test_transition_rejects_signed_to_unsigned_downgrade_under_same_repository(self):
        grant, candidate = self.prepare_transition()
        candidate_scope, _, authorization = self.unsigned(bundle=candidate)
        write(self.policy, dict(self.scope, unsigned_permit_authority=candidate_scope["unsigned_permit_authority"]))
        self.run_transition(dict(grant, to_source_policy=candidate_scope["source_policy"], to_authorization=authorization),
                            candidate, "publisher repository or issuer")

    def test_transition_retains_the_earliest_unsigned_permit_expiry(self):
        grant, candidate = self.prepare_transition()
        now = int(time.time())
        _, _, current = self.unsigned(request={"expires": now + 90})
        scope, permit, authorization = self.unsigned(bundle=candidate, request={"expires": now + 45})
        self.run_transition(dict(grant, from_authorization=current, to_source_policy=scope["source_policy"],
                                 to_authorization=authorization), candidate, fresh_until=permit["expires"])

    def test_transition_can_renew_the_exact_unsigned_source_with_a_new_permit(self):
        grant, candidate = self.prepare_transition()
        now = int(time.time())
        _, current_permit, current = self.unsigned(request={"expires": now + 90})
        shutil.rmtree(candidate)
        shutil.copytree(self.bundle, candidate)
        scope, candidate_permit, authorization = self.unsigned(bundle=candidate, request={"expires": now + 180})
        self.assertNotEqual(current_permit["revocation_id"], candidate_permit["revocation_id"])
        self.run_transition(dict(grant, from_authorization=current, to_source_policy=scope["source_policy"],
                                 to_authorization=authorization), candidate, fresh_until=current_permit["expires"])

    def test_transition_requires_a_health_check(self):
        grant, candidate = self.prepare_transition(launch={"healthcheck": None})
        self.run_transition(grant, candidate, "declared health check")

    def test_transition_rejects_an_identical_executable_and_launch(self):
        grant, candidate = self.prepare_transition(root=bytes(4096))
        self.assertNotEqual((self.bundle / "workload.raw").read_bytes(), (candidate / "workload.raw").read_bytes())
        self.run_transition(grant, candidate, "does not change executable or launch bytes")


if __name__ == "__main__":
    unittest.main()
