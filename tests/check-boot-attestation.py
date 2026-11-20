#!/usr/bin/env python3
"""Exercise the release client's collector and verifier against a disposable TPM 2.0."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

PCRS = "sha256:0,2,4,7,9,11,12,13"
KEY = "0x81004656"
PARENT = "0x81014656"
ATTRIBUTES = "fixedtpm|fixedparent|sensitivedataorigin|adminwithpolicy|noda|restricted|sign"


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

    run("--collect-boot-quote", "00" * 32, failure="TPM could not collect a boot quote")
    reference = enroll(socket, directory)
    save("reference.json", reference)
    quote(issue("first"))
    verdict = json.loads(appraise("first"))
    assert verdict == {"result": "measured-boot-matches-reference", "role": "hypervisor",
                       "host": reference["host"], "release_manifest_sha256": "42" * 32}
    appraise("first", failure="already consumed")

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
