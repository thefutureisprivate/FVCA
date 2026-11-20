#!/usr/bin/env python3
"""Qualify the HTTPS transport against signed release-intake fixtures and an isolated TLS depot."""

import argparse
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
from threading import Thread
import time

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

PREFIX = "/fvca/depot/"
METADATA_LIMIT = 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def certificate(directory, name, authority=None):
    key = ed25519.Ed25519PrivateKey.generate()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(UTC)
    builder = (x509.CertificateBuilder().subject_name(subject).public_key(key.public_key())
               .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(hours=1))
               .not_valid_after(now + timedelta(days=1))
               .add_extension(x509.BasicConstraints(ca=authority is None, path_length=None), critical=True))
    issuer, signing_key = authority or (subject, key)
    builder = builder.issuer_name(issuer)
    if authority:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
    pem = directory / f"{name}.pem"
    pem.write_bytes(builder.sign(signing_key, algorithm=None).public_bytes(serialization.Encoding.PEM))
    secret = directory / f"{name}.key"
    secret.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    return pem, secret, (subject, key)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format, *_args):
        pass

    def do_CONNECT(self):
        self.server.requests.append(self.path)
        self.send_error(403)

    def do_GET(self):
        self.server.requests.append(self.path)
        relative = self.path.removeprefix(PREFIX)
        parts = relative.split("/")
        if relative == self.path or len(parts) != 2 or parts[0] not in ("metadata", "targets"):
            self.send_error(404)
            return
        file = self.server.depot / relative
        if not file.is_file():
            self.send_error(404)
            return
        failure = self.server.failures.get(relative)
        if failure == "redirect":
            self.send_response(302)
            self.send_header("Location", self.server.redirect)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if failure == "forbidden":
            self.send_error(403)
            return
        self.send_response(200)
        if failure == "chunked":
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            chunk = b"x" * (METADATA_LIMIT + 1)
            self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n0\r\n\r\n")
            return
        length = METADATA_LIMIT + 1 if failure == "too-large" else file.stat().st_size
        self.send_header("Content-Length", str(length))
        if failure == "encoded":
            self.send_header("Content-Encoding", "gzip")
        self.end_headers()
        if failure == "slow":
            time.sleep(4)
        if failure in ("truncate", "too-large"):
            self.close_connection = True
        if failure == "too-large":
            return
        with file.open("rb") as source:
            if failure == "truncate":
                self.wfile.write(source.read(64 * 1024))
            else:
                shutil.copyfileobj(source, self.wfile)


class Server(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        if not isinstance(sys.exception(), (BrokenPipeError, ConnectionResetError, ssl.SSLError)):
            super().handle_error(request, client_address)


@contextmanager
def serve(depot, tls=None):
    with Server(("127.0.0.1", 0), Handler) as server:
        server.requests = []
        server.depot = depot
        server.failures = {}
        server.redirect = None
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(*tls)
            server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            thread.join()


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def fixture(client, source, output):
    output.mkdir(mode=0o700)
    ca, _, authority = certificate(output, "release-test-ca")
    unrelated, _, _ = certificate(output, "other-ca")
    leaf, key, _ = certificate(output, "localhost", authority)
    original = source / "depot-1"
    pinned = original / "metadata/1.root.json"
    host = json.loads((source / "selection-stage-hypervisor.json").read_text())
    guest = json.loads((source / "selection-stage-guest.json").read_text())
    host_stage = source / "state-stage-hypervisor/staged" / host["manifest_sha256"]
    guest_stage = source / "state-stage-guest/staged" / guest["manifest_sha256"]

    def run(name, depot, selection, *, state_name=None, expected=None, failure=None, env=None):
        state = output / f"state-{state_name or name}"
        state.mkdir(mode=0o700, exist_ok=True)
        config = output / f"{name}-depot.json"
        config.write_text(json.dumps(depot))
        request = output / f"{name}-selection.json"
        request.write_text(json.dumps(selection))
        command = [client, pinned, config, state, request]
        result = subprocess.run(command, capture_output=True, text=True, timeout=120, env=env, check=False)
        (output / f"{name}.log").write_text(result.stdout + result.stderr)
        if failure:
            require(result.returncode != 0 and failure.lower() in result.stderr.lower() and not result.stdout,
                    f"{name} did not reject for {failure!r}: {result}")
        else:
            require(result.returncode == 0 and result.stdout.startswith("FVCA_RELEASE_STAGED "),
                    f"{name} failed: {result}")
            stage = state / "staged" / selection["manifest_sha256"]
            require({item.name: digest(item) for item in stage.iterdir()}
                    == {item.name: digest(item) for item in expected.iterdir()}, "staged bytes differ from local intake")
        require(not list((state / "staged").glob(".stage-*")), f"{name} left a partial stage")
        print(f"{name} passed", flush=True)
        return state

    with serve(original) as trap, serve(original, (leaf, key)) as depot:
        base_url = f"https://localhost:{depot.server_port}{PREFIX}"
        trusted = {"transport": "https", "base_url": base_url, "ca_file": str(ca), "deadline_seconds": 45}
        proxy = f"http://127.0.0.1:{trap.server_port}"
        env = os.environ | {"HTTP_PROXY": proxy, "HTTPS_PROXY": proxy, "ALL_PROXY": proxy, "NO_PROXY": "",
                            "http_proxy": proxy, "https_proxy": proxy, "all_proxy": proxy, "no_proxy": ""}
        run("https-hypervisor", trusted, host, expected=host_stage, env=env)
        require(not trap.requests, "client used an ambient proxy")
        run("https-guest", trusted, guest, expected=guest_stage)
        run("untrusted-ca", trusted | {"ca_file": str(unrelated)}, guest, failure="UnknownIssuer")
        run("wrong-hostname", trusted | {"base_url": base_url.replace("localhost", "127.0.0.1")}, guest,
            failure="certificate not valid for name")
        run("cleartext-url", trusted | {"base_url": base_url.replace("https:", "http:")}, guest,
            failure="requires an HTTPS directory URL")
        run("controller-url", trusted, guest | {"base_url": proxy}, failure="unknown field")

        depot.redirect = proxy + "/redirected"
        depot.failures = {"metadata/2.root.json": "redirect"}
        # The fixture presents this file so the test can replace its response and distinguish it from HTTP 404.
        depot.depot = source / "rotated"
        run("redirect", trusted, guest, failure="302")
        require(not trap.requests, "client contacted a redirect destination")
        depot.failures = {"metadata/2.root.json": "forbidden"}
        run("forbidden-root", trusted, guest, failure="403")
        depot.depot = original

        depot.failures = {"metadata/timestamp.json": "encoded"}
        run("encoded-response", trusted, guest, failure="returned an encoded body")

        for mode in ("too-large", "chunked", "slow"):
            depot.failures = {"metadata/timestamp.json": mode}
            if mode == "slow":
                started = time.monotonic()
                run("deadline", trusted | {"deadline_seconds": 1}, guest, failure="timed out")
                require(time.monotonic() - started < 3, "request outlived the depot deadline")
            else:
                run(f"metadata-{mode}", trusted, guest, failure="exceeds its size bound")

        depot.depot = source / "same-root"
        runtime = next((depot.depot / "targets").glob("*.hypervisor-17-vm-runtime.raw"))
        depot.failures = {f"targets/{runtime.name}": "truncate"}
        state = run("truncated-artifact", trusted, host, failure="decoding response body")
        require(not list((state / "staged").iterdir()), "interrupted transfer published a release")
        depot.failures = {}
        run("transfer-retry", trusted, host, state_name="truncated-artifact", expected=host_stage)
        depot.depot = original
        run("https-rollback", trusted, host, state_name="truncated-artifact", failure="previously fetched version")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("client", "fixture", "output"):
        parser.add_argument(f"--{name}", type=lambda value: Path(value).absolute(), required=True)
    args = parser.parse_args()
    os.umask(0o077)
    fixture(args.client, args.fixture, args.output)


if __name__ == "__main__":
    main()
