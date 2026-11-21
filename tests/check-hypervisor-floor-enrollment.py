#!/usr/bin/env python3
"""Qualify one-time floor enrollment and interrupted initialization on a disposable TPM."""

import argparse
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import runpy
import selectors
import subprocess
import tempfile

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils


boot_test = runpy.run_path(Path(__file__).with_name("check-boot-attestation.py"))
INDEX = "0x01504656"
CHALLENGE = b"FVCA_HYPERVISOR_FLOOR_ENROLLMENT_CHALLENGE "
ENROLLED = b"FVCA_HYPERVISOR_FLOOR_ENROLLED "


def exercise(client, work, socket):
    def command(name, *args, **options):
        return subprocess.run([name, "-T", f"swtpm:path={socket}", *args], cwd=work,
                              timeout=20, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **options)

    def owner_command(credential, name, *args, **options):
        with tempfile.NamedTemporaryFile(dir=work) as encoded:
            encoded.write(b"hex:" + credential.read_bytes().hex().encode("ascii"))
            encoded.flush()
            return command(name, *args, f"file:{encoded.name}", **options)

    key = ec.generate_private_key(ec.SECP256R1())
    (work / "increment.pem").write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    command("tpm2_loadexternal", "-C", "o", "-G", "ecc", "-u", "increment.pem", "-c", "increment.ctx", check=True)
    command("tpm2_readpublic", "-c", "0x80000000", "-f", "tss", "-o", "increment.tpm2b", check=True)
    command("tpm2_flushcontext", "-t", check=True)
    reference = b"FVCA-HYPERVISOR-FLOOR-1\0" + os.urandom(16)
    (work / "reference.bin").write_bytes(reference)
    owner = work / "owner.bin"
    owner.write_bytes(os.urandom(12) + b"\0" + os.urandom(18) + b"\n")
    owner_command(owner, "tpm2_changeauth", "-c", "owner", check=True)
    ed = ed25519.Ed25519PrivateKey.generate()
    (work / "authority.pub").write_bytes(ed.public_key().public_bytes_raw())
    env = os.environ | {"FVCA_TEST_SWTPM_SOCKET": str(socket)}
    state = work / "state"
    state.mkdir(mode=0o700)
    enrollment = state / "floor-enrollment"
    prepare = [client, "--inspect-hypervisor-floor-enrollment", "increment.tpm2b", "reference.bin"]

    def snapshot():
        return json.loads(subprocess.check_output(prepare, env=env, cwd=work, timeout=20))

    def invocation(label, document, *, tamper=False, directory=state, credential=owner):
        raw = json.dumps(document).encode("ascii") + b"\n"
        (work / f"{label}.json").write_bytes(raw + (b" " if tamper else b""))
        (work / f"{label}.sig").write_bytes(ed.sign(raw))
        return [client, "--enroll-hypervisor-floor", directory, f"{label}.json", f"{label}.sig",
                "authority.pub", "increment.tpm2b", "reference.bin", credential]

    def run(label, document, refusal=None, **options):
        args = invocation(label, document, **options)
        job = subprocess.run(args, env=env, cwd=work, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20)
        if refusal is None:
            assert job.returncode == 0 and ENROLLED in job.stdout, job.stdout
        else:
            assert job.returncode != 0 and refusal in job.stdout, job.stdout
        assert CHALLENGE not in job.stdout
        print(f"{label} passed", flush=True)

    def nonce(job):
        with selectors.DefaultSelector() as poll:
            poll.register(job.stdout, selectors.EVENT_READ)
            assert poll.select(12), "expected a TPM enrollment challenge"
            line = job.stdout.readline()
        assert line.startswith(CHALLENGE), line
        payload = json.loads(line[len(CHALLENGE):])
        message = bytes.fromhex(payload["message"])
        assert payload["target"] == approved["target"]
        assert len(message) == 108 and message[-40:] == reference
        assert 0 < int.from_bytes(message[32:36], "big") <= 300
        command("tpm2_nvincrement", INDEX, "-C", INDEX, "--cphash", "cp.hash", check=True)
        assert (work / "cp.hash").read_bytes() == b"\x00\x20" + message[36:68]
        return message

    def sign(message):
        r, s = utils.decode_dss_signature(key.sign(message, ec.ECDSA(hashes.SHA256())))
        return (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex().encode("ascii") + b"\n"

    def start(label, document):
        return subprocess.Popen(invocation(label, document), env=env, cwd=work,
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    observed = snapshot()
    assert observed["counter"] == "absent"
    assert observed["target"]["ak_qualified_name"] == (work / "ak.qname").read_bytes().hex()
    assert observed["target"]["increment_key_sha256"] == hashlib.sha256(
        (work / "increment.tpm2b").read_bytes()).hexdigest()
    assert observed["target"]["policy_reference_sha256"] == hashlib.sha256(reference).hexdigest()
    stamp = int(datetime.now(UTC).timestamp())
    approved = {"schema": "fvca-hypervisor-floor-enrollment-v1",
                "valid_from": stamp - 30, "expires": stamp + 1200, "target": observed["target"]}
    expired = approved | {"valid_from": stamp - 120, "expires": stamp - 1}
    run("unsigned-change", approved, b"approval signature is invalid", tamper=True)
    run("expired", expired, b"outside its validity interval")
    run("different-tpm", approved | {
        "target": approved["target"] | {"ak_qualified_name": "000b" + "11" * 32},
    }, b"live TPM identity or proposed counter policy differs")
    owner.chmod(0o644)
    run("exposed-owner-authorization", approved, b"expected a private 32-byte owner authorization file")
    owner.chmod(0o600)
    assert snapshot()["counter"] == "absent"
    assert not enrollment.exists()
    unrelated = work / "unrelated"
    unrelated.mkdir(mode=0o700)
    wrong_owner = work / "wrong-owner.bin"
    wrong_owner.write_bytes(os.urandom(32))
    run("owner-authorization-required", approved, b"define the owner-authorized floor counter",
        directory=unrelated, credential=wrong_owner)
    wrong_owner.unlink()
    assert snapshot()["counter"] == "absent"

    with start("interrupted", approved) as job:
        interrupted = nonce(job)
        assert (enrollment / "intent.json").is_file()
        assert (enrollment / "defined.json").is_file()
        job.kill()
        job.communicate(timeout=10)
    command("tpm2_flushcontext", "-s", check=True)
    command("tpm2_flushcontext", "-t", check=True)
    assert snapshot()["counter"] == "uninitialized"
    assert command("tpm2_nvincrement", INDEX, "-C", INDEX).returncode != 0
    assert owner_command(owner, "tpm2_nvincrement", INDEX, "-C", "o", "-P").returncode != 0
    other = work / "other"
    other.mkdir(mode=0o700)
    run("unowned-pending-counter", approved, b"has no matching enrollment intent", directory=other)
    print("interruption left a policy-only, unwritten counter", flush=True)

    custody = work / "owner-custody.bin"
    owner.rename(custody)
    with start("replayed-signature", approved) as job:
        assert nonce(job) != interrupted
        output = job.communicate(sign(interrupted), timeout=20)[0]
        assert job.returncode and b"authorize the live session signature" in output, output
    assert snapshot()["counter"] == "uninitialized"

    with start("completed", approved) as job:
        live = nonce(job)
        output = job.communicate(sign(live), timeout=20)[0]
        assert job.returncode == 0 and ENROLLED in output, output
    status = snapshot()
    assert status["counter"] == "initialized"
    command("tpm2_nvread", INDEX, "-C", INDEX, "-s", "8", "-o", "observed.floor", check=True)
    floor = int.from_bytes((work / "observed.floor").read_bytes(), "big")
    assert floor > 0
    expected = (f"FVCA-HYPERVISOR-EPOCH-1\nepoch={floor}\n"
                f"policy_sha256={approved['target']['epoch_policy_sha256']}\n").encode("ascii")
    receipt = enrollment / "epoch.conf"
    assert receipt.read_bytes() == expected
    run("initialized-from-another-state", approved, b"has no matching enrollment receipt", directory=other)
    run("idempotent", approved)
    receipt.unlink()
    run("readback-after-lost-receipt", expired)
    assert receipt.read_bytes() == expected
    command("tpm2_nvread", INDEX, "-C", INDEX, "-s", "8", "-o", "after.floor", check=True)
    assert (work / "observed.floor").read_bytes() == (work / "after.floor").read_bytes()
    print(f"one authorized increment initialized floor {floor} and subsequent readback preserved it", flush=True)

    owner_command(custody, "tpm2_nvundefine", INDEX, "-C", "o", "-P", check=True)
    run("removed-counter-fenced", approved, b"previously defined floor counter is missing", credential=custody)
    assert snapshot()["counter"] == "absent"
    owner_command(custody, "tpm2_nvdefine", INDEX, "-C", "o", "-g", "sha256", "-s", "8",
                  "-a", "authread|authwrite|no_da", "-P", check=True)
    run("foreign-index-fenced", approved, b"verify the reserved floor counter's public area", credential=custody)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("client", type=lambda path: Path(path).resolve(strict=True))
    os.umask(0o077)
    client = parser.parse_args().client
    with tempfile.TemporaryDirectory(prefix="fvca-floor-enroll-", dir="/tmp") as temporary:
        work = Path(temporary)
        with boot_test["emulator"](work) as socket:
            boot_test["enroll"](socket, work)
            exercise(client, work, socket)
