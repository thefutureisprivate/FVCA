#!/usr/bin/env python3
"""Qualify signed unsigned-source issuance and failed discovery decisions."""

from contextlib import redirect_stderr, redirect_stdout
from email.message import Message
from http.client import HTTPSConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import io
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
from threading import Thread
import time
from unittest import TestCase, main, mock
from uuid import uuid4

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

from image_verity import verify_cms
from workload_discovery import discover
import workload_oci as oci
from workload_permit import ACKNOWLEDGMENT, OPERATOR_ROLE

spec = importlib.util.spec_from_file_location("issuer", TOOLS / "issue-workload-permit.py")
issuer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(issuer)


def response(status, content_type, body, **headers):
    message = Message()
    message["Content-Type"] = content_type
    for name, value in headers.items():
        message[name] = value
    return status, message, body if isinstance(body, bytes) else oci.json_bytes(body)


def referrers(manifests):
    return {"schemaVersion": 2, "mediaType": oci.INDEX, "manifests": manifests}


def missing(code="MANIFEST_UNKNOWN"):
    return response(404, "application/json", {"errors": [{"code": code}]})


def source(work):
    layout = work / "oci"
    (layout / "blobs/sha256").mkdir(parents=True)

    def blob(raw, kind):
        digest = oci.sha256(raw)
        oci.blob_path(layout, digest).write_bytes(raw)
        return {"mediaType": kind, "digest": digest, "size": len(raw)}

    layer = blob(b"fixture layer", oci.LAYER)
    config = {"Entrypoint": ["/bin/service"], "Cmd": ["--foreground"], "User": "2000:2000",
              "Env": ["TZ=UTC"], "Volumes": {"/data": {}}, "Healthcheck": {"Test": ["CMD", "/bin/probe"]}}
    config_entry = blob(oci.json_bytes({**oci.PLATFORM, "config": config,
                                      "rootfs": {"type": "layers", "diff_ids": [layer["digest"]]}}), oci.CONFIG)
    manifest = oci.json_bytes({"schemaVersion": 2, "mediaType": oci.MANIFEST,
                               "config": config_entry, "layers": [layer]})
    selected = blob(manifest, oci.MANIFEST)
    index = oci.json_bytes(referrers([{**selected, "platform": oci.PLATFORM}]))
    (layout / "oci-layout").write_bytes(oci.json_bytes({"imageLayoutVersion": "1.0.0"}))
    (layout / "index.json").write_bytes(oci.json_bytes(referrers([selected])))
    (work / "index.json").write_bytes(index)
    policy = {"schema": "fvca-oci-explicit-exceptions-v1", "service": "mail", "repository": "registry.fvca.test/demo/mail",
              "index": oci.sha256(index), "manifest": selected["digest"], "uid": 2000, "gid": 2000, "volumes": ["/data"]}
    return policy, config, index, manifest


def sign(record, signature, signer):
    subprocess.run([
        "openssl", "cms", "-sign", "-binary", "-noattr", "-nocerts", "-outform", "DER", "-in", record,
        "-out", signature, "-signer", signer.with_suffix(".crt"), "-inkey", signer.with_suffix(".key"),
    ], check=True, capture_output=True)


class PermitTests(TestCase):
    @classmethod
    def setUpClass(cls):
        work = cls.enterClassContext(tempfile.TemporaryDirectory(prefix="fvca-permit-signers-"))
        cls.signers = Path(work)
        for name in ("authority", "operator", "other"):
            subprocess.run([
                "openssl", "req", "-new", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                "-noenc", "-days", "1", "-subj", f"/CN={name}", "-out", cls.signers / f"{name}.crt",
                "-keyout", cls.signers / f"{name}.key",
            ], check=True, capture_output=True)

    def setUp(self):
        self.work = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="fvca-permit-")))
        self.policy, self.config, index, manifest = source(self.work)
        self.policy["permit_authority"] = issuer.certificate_identity(self.signers / "authority.crt")[0]
        self.policy_path = self.work / "policy.json"
        self.policy_path.write_bytes(oci.json_bytes(self.policy))
        self.launch = self.work / "launch.json"
        self.launch.write_bytes(oci.json_bytes(oci.launch_metadata(self.policy, self.config)))
        scope = {"operator": "reviewer", "role": OPERATOR_ROLE, "guest": "guest-one", "service": "mail",
                 "repository": self.policy["repository"], "source_policy": oci.sha256(self.policy_path.read_bytes())}
        now = int(time.time())
        self.delegation = {**scope, "schema": "fvca-workload-permit-delegation-v1",
                           "operator_certificate": issuer.certificate_identity(self.signers / "operator.crt")[0],
                           "max_permit_seconds": 600, "valid_from": now - 100, "expires": now + 1000,
                           "registry_token_service": None}
        self.ack = {**scope, "schema": "fvca-workload-permit-request-v1", "source_index": self.policy["index"],
                    "manifest": self.policy["manifest"], "platform": oci.PLATFORM, "launch": oci.sha256(self.launch.read_bytes()),
                    "acknowledgment": ACKNOWLEDGMENT, "reason": "Reviewed the exact fixture source",
                    "requested_at": now - 1, "expires": now + 120, "revocation_id": str(uuid4()),
                    "revocation_action": "block-new-starts"}
        self.responses = {}
        for digest, raw, kind in ((self.policy["index"], index, oci.INDEX), (self.policy["manifest"], manifest, oci.MANIFEST)):
            base = "/v2/demo/mail"
            tag = digest.replace(":", "-", 1)
            self.responses[f"{base}/manifests/{digest}"] = response(200, kind, raw)
            self.responses[f"{base}/manifests/{tag}"] = missing()
            self.responses[f"{base}/manifests/{tag}.sig"] = missing()
            self.responses[f"{base}/referrers/{digest}"] = response(200, oci.INDEX, referrers([]))

    def respond(self, host, path, headers, _context):
        self.assertEqual("registry.fvca.test", host)
        self.assertIn(oci.INDEX, headers["Accept"])
        return self.responses[path]

    def cli(self, *, request_signer="operator", alter=None, output="approved"):
        for base, data, signer in (("delegation", self.delegation, "authority"), ("request", self.ack, request_signer)):
            record, signature = self.work / f"{base}.json", self.work / f"{base}.p7s"
            record.write_bytes(oci.json_bytes(data))
            sign(record, signature, self.signers / signer)
        if alter:
            (self.work / "request.json").write_bytes(oci.json_bytes(self.ack | alter))
        paths = {"policy": self.policy_path, "layout": self.work / "oci", "source-index": self.work / "index.json",
                 "launch": self.launch, "authority-key": self.signers / "authority.key", "output": self.work / output}
        for name in ("authority", "operator"):
            paths[f"{name}-certificate"] = self.signers / f"{name}.crt"
        for name in ("delegation", "request"):
            paths[name] = self.work / f"{name}.json"
            paths[f"{name}-signature"] = self.work / f"{name}.p7s"
        argv = ["issuer", "issue", *(item for key, value in paths.items() for item in (f"--{key}", str(value)))]
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "argv", argv), redirect_stdout(stdout), redirect_stderr(stderr):
            issuer.main()
        return stdout.getvalue()

    def test_issue_and_retain_signed_evidence(self):
        preview = subprocess.check_output([
            sys.executable, "-B", "-W", "error", TOOLS / "issue-workload-permit.py", "preview", "--policy", self.policy_path,
            "--source-index", self.work / "index.json", "--layout", self.work / "oci",
        ])
        self.assertEqual(self.launch.read_bytes(), preview)
        with mock.patch("workload_discovery.request", side_effect=self.respond) as request:
            self.assertIn(self.ack["revocation_id"], self.cli())
            self.assertEqual(request.call_count, 8)
        approved = self.work / "approved"
        self.assertEqual(approved.stat().st_mode & 0o777, 0o700)
        self.assertFalse(list(approved.glob("*.key")))
        record = approved / "permit.json"
        verify_cms(record, approved / "permit.p7s", self.signers / "authority.crt")
        permit = oci.parse_json(record.read_bytes())
        self.assertEqual(permit["provenance"], "UNSIGNED_UPSTREAM_APPROVED")
        self.assertEqual(permit["acknowledgment"], self.ack)
        self.assertEqual(permit["expiry_action"], "block-new-starts")
        self.assertEqual(permit["request_sha256"], oci.sha256((approved / "request.json").read_bytes()))

    def test_bad_scope_signature_or_warning_blocks_discovery(self):
        for changes, extra in (
            ({"acknowledgment": ACKNOWLEDGMENT.lower()}, {}), ({"guest": "guest-two"}, {}),
            ({"manifest": self.policy["index"]}, {}), ({"platform": {"os": "linux", "architecture": "arm64"}}, {}),
            ({"expires": int(time.time()) - 2}, {}), ({}, {"request_signer": "other"}), ({}, {"alter": {"reason": "Modified"}}),
        ):
            with self.subTest(changes=changes, extra=extra), mock.patch("workload_discovery.request") as request:
                before = self.ack
                try:
                    self.ack = before | changes
                    with self.assertRaises(SystemExit) as exit_status:
                        self.cli(**extra)
                    self.assertEqual(exit_status.exception.code, 1)
                    request.assert_not_called()
                    self.assertFalse((self.work / "approved").exists())
                finally:
                    self.ack = before

    def test_signed_only_policy_has_no_exception(self):
        self.policy["schema"] = "fvca-oci-source-v1"
        del self.policy["permit_authority"]
        self.policy.update(certificate_identity="https://registry.fvca.test/signing/workflow",
                           certificate_issuer="https://registry.fvca.test/issuer")
        oci.validate_policy(self.policy)
        self.policy_path.write_bytes(oci.json_bytes(self.policy))
        with mock.patch("workload_discovery.request") as request, self.assertRaises(SystemExit):
            self.cli()
        request.assert_not_called()
        self.assertFalse((self.work / "approved").exists())

    def test_discovery_refuses_present_ambiguous_and_failed_evidence(self):
        base = "/v2/demo/mail"
        digest = self.policy["manifest"]
        tag = digest.replace(":", "-", 1)
        api, legacy, fallback = f"{base}/referrers/{digest}", f"{base}/manifests/{tag}.sig", f"{base}/manifests/{tag}"
        for endpoint, answer in (
            (api, response(200, oci.INDEX, referrers([{"digest": digest}]))),
            (api, response(200, oci.INDEX, referrers([]), Link='</next>; rel="next"')),
            (api, response(200, oci.INDEX, referrers([]), **{"OCI-Filters-Applied": "artifactType"})),
            (api, response(503, "application/json", {})), (api, missing("DENIED")),
            (fallback, response(200, oci.INDEX, referrers([{"digest": digest}]))),
            (legacy, response(200, oci.MANIFEST, {})), (legacy, missing("NAME_UNKNOWN")),
            (legacy, response(403, "application/json", {})), (legacy, response(302, "text/plain", b"")),
            (f"{base}/manifests/{digest}", response(200, oci.MANIFEST, {"schemaVersion": 2})),
        ):
            with self.subTest(endpoint=endpoint, status=answer[0]), mock.patch.dict(self.responses, {endpoint: answer}):
                with mock.patch("workload_discovery.request", side_effect=self.respond), self.assertRaises(ValueError):
                    discover(self.policy, None)
        with mock.patch.dict(self.responses, {legacy: response(200, oci.MANIFEST, {})}):
            with mock.patch("workload_discovery.request", side_effect=self.respond), self.assertRaises(SystemExit):
                self.cli()
        self.assertFalse((self.work / "approved").exists())

    def test_legacy_referrers_and_scoped_token(self):
        self.responses[f"/v2/demo/mail/referrers/{self.policy['index']}"] = response(404, "text/plain", b"404 page not found\n")

        def respond(host, path, headers, context):
            if host == "tokens.fvca.test":
                self.assertEqual(path, "/token?service=oci&scope=repository%3Ademo%2Fmail%3Apull")
                self.assertNotIn("Authorization", headers)
                return response(200, "application/json", {"token": "test-token"})
            self.assertEqual(headers["Authorization"], "Bearer test-token")
            return self.respond(host, path, headers, context)

        with mock.patch("workload_discovery.request", side_effect=respond) as request:
            observed = discover(self.policy, {"url": "https://tokens.fvca.test/token", "service": "oci"})
            self.assertEqual(observed["subjects"][0]["referrers_api"]["status"], 404)
            self.assertEqual(request.call_count, 9)

    def test_discovery_over_validated_https(self):
        cert, key = self.work / "registry.crt", self.work / "registry.key"
        subprocess.run([
            "openssl", "req", "-new", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-noenc",
            "-days", "1", "-subj", "/CN=registry.fvca.test", "-addext", "subjectAltName=DNS:registry.fvca.test",
            "-out", cert, "-keyout", key,
        ], check=True, capture_output=True)
        server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_tls.load_cert_chain(cert, key)
        client_tls = ssl.create_default_context(cafile=cert)
        responses = self.responses

        class RegistryHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                status, headers, body = responses[self.path]
                self.send_response(status)
                for name, value in headers.items():
                    self.send_header(name, value)
                if "Content-Length" not in headers:
                    self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        def connect(host, timeout, context):
            return HTTPSConnection(host, port=server.server_port, timeout=timeout, context=context)

        getaddrinfo = socket.getaddrinfo
        with ThreadingHTTPServer(("127.0.0.1", 0), RegistryHandler) as server:
            server.socket = server_tls.wrap_socket(server.socket, server_side=True)
            worker = Thread(target=server.serve_forever)
            worker.start()
            try:
                with mock.patch("workload_discovery.HTTPSConnection", side_effect=connect), mock.patch(
                    "socket.getaddrinfo", side_effect=lambda _name, port, *args: getaddrinfo("127.0.0.1", port, *args),
                ):
                    with mock.patch("workload_discovery.ssl.create_default_context", return_value=client_tls):
                        self.assertIn(self.ack["revocation_id"], self.cli())
                    wrong_host = self.policy | {"repository": "other.fvca.test/demo/mail"}
                    with self.assertRaises(ssl.SSLCertVerificationError):
                        discover(wrong_host, None, context=client_tls)
                    responses[f"/v2/demo/mail/referrers/{self.policy['index']}"][1]["Content-Length"] = "4096"
                    with self.assertRaisesRegex(ValueError, "incomplete"):
                        discover(self.policy, None, context=client_tls)
            finally:
                server.shutdown()
                worker.join(timeout=5)


if __name__ == "__main__":
    main()
