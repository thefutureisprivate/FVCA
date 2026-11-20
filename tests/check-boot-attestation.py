#!/usr/bin/env python3
"""Exercise the release client's collector and verifier against a disposable TPM 2.0."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import socket as network
import ssl
import struct
import subprocess
import tempfile
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

PCRS = "sha256:0,2,4,7,9,11,12,13"
KEY = "0x81004656"
PARENT = "0x81014656"
ATTRIBUTES = "fixedtpm|fixedparent|sensitivedataorigin|adminwithpolicy|noda|restricted|sign"
ALPN = "fvca-management/1"
GUEST = "e629aa43-af11-47c6-aedc-a2dc47f1cc3a"


@contextmanager
def emulator(directory):
    state = directory / "tpm"
    state.mkdir()
    socket = directory / "tpm.sock"
    with subprocess.Popen([
        "swtpm", "socket", "--tpm2", "--tpmstate", f"dir={state}",
        "--server", f"type=unixio,path={socket}", "--ctrl", f"type=unixio,path={socket}.ctrl",
        "--flags", "not-need-init,startup-clear",
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as process:
        try:
            deadline = time.monotonic() + 5
            while not socket.is_socket() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.05)
            if not socket.is_socket():
                raise RuntimeError("disposable TPM socket did not start")
            yield socket
        finally:
            process.terminate()
            process.wait(timeout=10)


def tool(socket, directory, command, *args):
    return subprocess.run([command, "-T", f"swtpm:path={socket}", *args], cwd=directory,
                          text=True, stdout=subprocess.PIPE, timeout=15, check=True).stdout


def enroll(socket, directory):
    for command, args in (
        ("tpm2_startauthsession", ("-S", "trial.ctx")),
        ("tpm2_policycommandcode", ("-S", "trial.ctx", "-L", "quote.policy", "TPM2_CC_Quote")),
        ("tpm2_flushcontext", ("trial.ctx",)),
        ("tpm2_createprimary", ("-C", "o", "-G", "ecc", "-c", "parent.ctx")),
        ("tpm2_evictcontrol", ("-C", "o", "-c", "parent.ctx", PARENT)),
        ("tpm2_flushcontext", ("-t",)),
        ("tpm2_create", ("-C", PARENT, "-G", "ecc256:ecdsa-sha256:null", "-g", "sha256", "-a", ATTRIBUTES,
                        "-L", "quote.policy", "-u", "ak.public", "-r", "ak.private")),
        ("tpm2_load", ("-C", PARENT, "-u", "ak.public", "-r", "ak.private", "-c", "ak.ctx")),
        ("tpm2_evictcontrol", ("-C", "o", "-c", "ak.ctx", KEY)),
        ("tpm2_flushcontext", ("-t",)),
        ("tpm2_readpublic", ("-c", KEY, "-f", "pem", "-o", "ak.pem", "-q", "ak.qname")),
        ("tpm2_pcrextend", ("7:sha256=" + "17" * 32, "11:sha256=" + "23" * 32)),
    ):
        tool(socket, directory, command, *args)
    observed = tool(socket, directory, "tpm2_pcrread", PCRS)
    parsed = re.findall(r"^\s*([0-9]+)\s*:\s*0x([0-9a-fA-F]{64})$", observed, re.MULTILINE)
    assert [int(index) for index, _ in parsed] == [0, 2, 4, 7, 9, 11, 12, 13], observed
    public = serialization.load_pem_public_key((directory / "ak.pem").read_bytes())
    return {
        "schema": "fvca-hypervisor-boot-reference-v1",
        "host": "ab5d051d-8851-4e99-9abc-94075da4d022",
        "release_manifest_sha256": "42" * 32,
        "ak_public": public.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex(),
        "ak_qualified_name": (directory / "ak.qname").read_bytes().hex(),
        "sha256_pcrs": [value.lower() for _, value in parsed],
    }


def management_certificates(directory):
    now = datetime.now(UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "FVCA TLS test CA")])
    authority = ec.generate_private_key(ec.SECP256R1())
    leaf = ec.generate_private_key(ec.SECP256R1())
    domain = "fvca-test.example"

    def certificate(subject, key):
        return (x509.CertificateBuilder().issuer_name(name).subject_name(subject).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
                .not_valid_after(now + timedelta(days=1)))

    ca = (certificate(name, authority).add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .sign(authority, hashes.SHA256()))
    server = (certificate(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)]), leaf)
              .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False)
              .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
              .sign(authority, hashes.SHA256()))
    (directory / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (directory / "server.pem").write_bytes(server.public_bytes(serialization.Encoding.PEM))
    key = directory / "server.key"
    key.touch(mode=0o600, exist_ok=False)
    key.write_bytes(leaf.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
    return domain, hashlib.sha256(server.public_bytes(serialization.Encoding.DER)).hexdigest()


def remote_appraisal(directory, run, reference, verdict):
    domain, pin = management_certificates(directory)
    operator = ed25519.Ed25519PrivateKey.generate()
    reader = ed25519.Ed25519PrivateKey.generate()
    for name, key in (("operator.key", operator), ("reader.key", reader)):
        path = directory / name
        path.touch(mode=0o600, exist_ok=False)
        path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    host = reference["host"]
    enrollment = {
        "schema": "fvca-hypervisor-management-v1",
        "host": host,
        "address": "127.0.0.1:8443",
        "gateway_uid": 62000,
        "gateway_gid": 62000,
        "tls_certificate_sha256": pin,
        "operator_public_key": reader.public_key().public_bytes_raw().hex(),
        "attestation_operator_public_key": operator.public_key().public_bytes_raw().hex(),
    }
    policy = directory / "management.json"
    options = ("--appraise-remote-boot", "reference.json", policy)

    def collect(request):
        return json.loads(run("--collect-boot-quote", request["operation"]["challenge"]))

    prior = None

    def serve(listener, context, response, expect_request):
        with listener.accept()[0] as stream:
            stream.settimeout(5)
            try:
                tls = context.wrap_socket(stream, server_side=True)
            except ssl.SSLError:
                assert not expect_request
                return
            with tls, tls.makefile("rb") as wire:
                size = wire.read(4)
                if not expect_request:
                    assert not size, "sent a signed request before authenticating the endpoint"
                    return
                assert tls.selected_alpn_protocol() == ALPN
                length = struct.unpack(">I", size)[0]
                assert 64 < length <= 2048
                data = wire.read(length)
                operator.public_key().verify(data[:64], data[64:])
                request = json.loads(data[64:])
                assert request["schema"] == "fvca-management-request-v1"
                assert request["host"] == host and request["guest"] == GUEST
                assert re.fullmatch("[0-9a-f]{32}", request["nonce"])
                assert request["issued_at"] <= time.time() < request["expires"]
                assert request["expires"] - request["issued_at"] <= 30
                assert request["operation"]["type"] == "boot-quote"
                assert re.fullmatch("[0-9a-f]{64}", request["operation"]["challenge"])
                envelope = {"schema": "fvca-management-response-v1", "result": "boot-quote",
                            "host": host, "guest": GUEST, "nonce": request["nonce"]}
                payload = json.dumps(envelope | response(request)).encode("ascii")
                tls.sendall(struct.pack(">I", len(payload)) + payload)

    def exchange(response=None, *, failure=None, expected_pin=pin, tls_name=domain, alpn=ALPN, ca="ca.pem"):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.num_tickets = 0
        context.set_alpn_protocols([alpn])
        context.load_cert_chain(directory / "server.pem", directory / "server.key")
        with network.socket() as listener, ThreadPoolExecutor(max_workers=1) as threads:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(5)
            record = dict(enrollment, address=f"127.0.0.1:{listener.getsockname()[1]}",
                          tls_certificate_sha256=expected_pin)
            policy.write_text(json.dumps(record), encoding="ascii")
            handling = threads.submit(serve, listener, context, response, response is not None)
            result = run(*options, ca, tls_name, "operator.key", failure=failure)
            handling.result(timeout=10)
            return result

    def initial_quote(request):
        nonlocal prior
        prior = collect(request)
        return {"evidence": prior}

    assert json.loads(exchange(initial_quote)) == verdict
    exchange(lambda _: {"evidence": prior}, failure="does not answer the verifier's challenge")
    exchange(lambda request: {"evidence": collect(request), "nonce": "0" * 32},
             failure="response does not match its request")
    exchange(lambda _: {"result": "refused", "code": "boot-quote-unavailable"},
             failure="Hypervisor could not collect a boot quote")
    exchange(lambda _: {"padding": "x" * 4096}, failure="management frame exceeds")
    exchange(expected_pin="ff" * 32, failure="protocol or certificate differs")
    exchange(alpn="another-protocol", failure="protocol or certificate differs")
    exchange(tls_name="wrong.example", failure="invalid peer certificate")
    exchange(ca="server.pem", failure="invalid peer certificate")
    policy.write_text(json.dumps(enrollment), encoding="ascii")
    run(*options, "ca.pem", domain, "reader.key", failure="attestation key differs")
    (directory / "operator.key").chmod(0o640)
    run(*options, "ca.pem", domain, "operator.key", failure="private attestation key with mode 0600")
    policy.write_text(json.dumps(dict(enrollment, host="f2e03a40-e8c9-4d24-942d-89ae70fefea2")),
                      encoding="ascii")
    run(*options, "ca.pem", domain, "operator.key", failure="name different Hosts")
    print("Remote appraisal passed pinned TLS 1.3, signed request, identity and fresh TPM checks")


def exercise(client, directory, socket):
    environment = dict(os.environ, FVCA_TEST_SWTPM_SOCKET=str(socket))

    def run(*args, stdin=None, failure=None):
        result = subprocess.run([client, *args], cwd=directory, env=environment, input=stdin,
                                text=True, capture_output=True, timeout=15)
        if failure is not None:
            assert result.returncode != 0 and not result.stdout and failure in result.stderr, result
        else:
            result.check_returncode()
        return result.stdout

    def save(name, record):
        path = directory / name
        path.write_text(json.dumps(record), encoding="ascii")

    def issue(pending, ref="reference.json"):
        return run("--issue-boot-challenge", ref, pending)

    def quote(nonce, output="quote.json"):
        (directory / output).write_text(run("--collect-boot-quote", stdin=nonce), encoding="ascii")

    def appraise(pending, evidence="quote.json", ref="reference.json", failure=None):
        return run("--appraise-boot-quote", ref, pending, evidence, failure=failure)

    run("--collect-boot-quote", "00" * 32, failure="expected a nonzero boot challenge")
    reference = enroll(socket, directory)
    save("reference.json", reference)
    quote(issue("first"))
    verdict = json.loads(appraise("first"))
    assert verdict == {"result": "measured-boot-matches-reference", "role": "hypervisor",
                       "host": reference["host"], "release_manifest_sha256": "42" * 32}
    appraise("first", failure="already consumed")
    remote_appraisal(directory, run, reference, verdict)

    issue("second")
    appraise("second", failure="does not answer the verifier's challenge")
    quote(issue("signature-challenge"))
    evidence = json.loads((directory / "quote.json").read_bytes())
    evidence["signature"] = "00" * 64
    save("altered.json", evidence)
    appraise("signature-challenge", "altered.json", failure="signature does not match")
    appraise("signature-challenge")

    updated = dict(reference, release_manifest_sha256="43" * 32)
    save("updated.json", updated)
    quote(issue("bound"))
    appraise("bound", ref="updated.json", failure="different trusted reference")
    appraise("bound")

    wrong_key = dict(reference, ak_qualified_name="000b" + "fe" * 32)
    save("wrong-key.json", wrong_key)
    quote(issue("wrong-key", "wrong-key.json"))
    appraise("wrong-key", ref="wrong-key.json", failure="signer name differs")

    nonce = issue("wrong-selection").strip()
    tool(socket, directory, "tpm2_startauthsession", "--policy-session", "-S", "quote.ctx")
    tool(socket, directory, "tpm2_policycommandcode", "-S", "quote.ctx", "TPM2_CC_Quote")
    tool(socket, directory, "tpm2_quote", "-c", KEY, "-p", "session:quote.ctx", "-l", "sha256:7,11",
         "-q", nonce, "-f", "plain", "-m", "other-selection.bin", "-s", "other-signature.der")
    tool(socket, directory, "tpm2_flushcontext", "quote.ctx")
    r, s = decode_dss_signature((directory / "other-signature.der").read_bytes())
    save("other-selection.json", {
        "schema": "fvca-hypervisor-boot-quote-v1",
        "quote": (directory / "other-selection.bin").read_bytes().hex(),
        "signature": (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex(),
    })
    appraise("wrong-selection", "other-selection.json", failure="unexpected boot quote PCR bank or selection")

    quote(issue("expired"))
    record = json.loads((directory / "expired").read_bytes())
    record["issued"] -= 120
    save("expired", record)
    appraise("expired", failure="outside its validity interval")

    quote(issue("race"))
    with ThreadPoolExecutor(max_workers=2) as threads:
        calls = [threads.submit(subprocess.run,
                                [client, "--appraise-boot-quote", "reference.json", "race", "quote.json"],
                                cwd=directory, text=True, capture_output=True, timeout=15) for _ in range(2)]
        responses = [call.result() for call in calls]
    assert sum(result.returncode == 0 for result in responses) == 1, responses
    assert sum(bool(result.stdout) for result in responses) == 1, responses

    tool(socket, directory, "tpm2_pcrextend", "10:sha256=" + "37" * 32)
    quote(issue("unselected-pcr"))
    appraise("unselected-pcr")
    tool(socket, directory, "tpm2_pcrextend", "11:sha256=" + "49" * 32)
    quote(issue("changed-boot"))
    appraise("changed-boot", failure="does not match the approved PCR measurements")
    print("Boot attestation passed TPM quote, single-use freshness, enrollment, and PCR checks")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("client", type=lambda name: Path(name).resolve(strict=True),
                        help="fvca-release-client built with --features swtpm-test")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="fvca-quote-") as temporary:
        directory = Path(temporary)
        with emulator(directory) as socket:
            exercise(args.client, directory, socket)
