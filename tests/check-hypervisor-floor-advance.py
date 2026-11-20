#!/usr/bin/env python3
"""Exercise the live maintenance transaction against a disposable TPM and signed disk pair."""

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import subprocess
import tempfile
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils


INDEX = "0x01504656"
CHALLENGE = b"FVCA_HYPERVISOR_FLOOR_CHALLENGE "
COMMITTED = b"FVCA_HYPERVISOR_FLOOR_COMMITTED "


@contextmanager
def software_tpm(state):
    with tempfile.TemporaryDirectory(prefix="fvca-floor-tpm-") as temporary:
        socket = Path(temporary) / "tpm.sock"
        command = [
            "swtpm", "socket", "--tpm2", "--tpmstate", f"dir={state}",
            "--server", f"type=unixio,path={socket}", "--ctrl", f"type=unixio,path={socket}.ctrl",
            "--flags", "not-need-init,startup-clear",
        ]
        with subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as emulator:
            try:
                deadline = time.monotonic() + 5
                while not socket.is_socket() and emulator.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.05)
                if not socket.is_socket():
                    raise RuntimeError("software TPM socket did not start")
                yield socket
            finally:
                emulator.terminate()
                emulator.wait(timeout=10)


def tool(socket, name, *operands):
    subprocess.run([name, "-T", f"swtpm:path={socket}", *operands], check=True, timeout=15,
                   stdout=subprocess.DEVNULL)


def counter(socket, output):
    path = output / "live-floor.bin"
    tool(socket, "tpm2_nvread", INDEX, "-C", INDEX, "-s", "8", "-o", path)
    data = path.read_bytes()
    assert len(data) == 8
    return int.from_bytes(data, "big")


def locked(path):
    with path.open("rb") as file:
        try:
            fcntl.flock(file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        return False


def qualify(args):
    private = serialization.load_pem_private_key(args.increment_key.read_bytes(), password=None)
    assert isinstance(private, ec.EllipticCurvePrivateKey) and private.curve.name == "secp256r1"
    raw = args.approval.read_bytes()
    approval = json.loads(raw)
    digest = hashlib.sha256(raw).hexdigest()
    old, target = approval["previous_floor"], approval["next_floor"]
    paths = [Path(approval[name]["disk"]["path"]) for name in ("primary", "recovery")]
    paths.append(args.state / "intake.lock")
    args.output.mkdir(mode=0o700)
    working = shutil.copytree(args.enrollment / "counter-one", args.output / "committed-tpm")
    already = shutil.copytree(args.enrollment / "counter-two", args.output / "unrelated-advance-tpm")
    reference = args.enrollment / "policy-reference.bin"
    program = [
        args.client, "--advance-hypervisor-floor", args.state, args.approval, args.signature,
        args.authority, args.certificate, args.enrollment / "authority.tpm2b", reference,
    ]
    receipt = COMMITTED + f"{target} {digest}\n".encode("ascii")
    transaction = args.state / "floor-transactions"
    intent = transaction / f"{digest}.intent"
    completed = transaction / f"{digest}.committed"
    assert not intent.exists() and not completed.exists()

    def execute(name, socket, *, expected=None, fail=None, command=program):
        result = subprocess.run(command, input=b"", stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                env=os.environ | {"FVCA_TEST_SWTPM_SOCKET": str(socket)}, timeout=120)
        (args.output / f"{name}.log").write_bytes(result.stdout)
        if fail:
            assert result.returncode and fail in result.stdout and COMMITTED not in result.stdout, result.stdout
        else:
            assert result.returncode == 0 and result.stdout == expected, result.stdout
        print(f"{name} passed", flush=True)

    def respond(name, socket, *, wrong_signature):
        with subprocess.Popen(program, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              env=os.environ | {"FVCA_TEST_SWTPM_SOCKET": str(socket)}) as client, \
                selectors.DefaultSelector() as poll:
            poll.register(client.stdout, selectors.EVENT_READ)
            received = bytearray()
            deadline = time.monotonic() + 120
            try:
                while poll.select(max(0, deadline - time.monotonic())):
                    chunk = os.read(client.stdout.fileno(), 4096)
                    if not chunk:
                        break
                    received.extend(chunk)
                    if any(line.startswith(CHALLENGE) for line in received.splitlines()) and b"\n" in received.partition(CHALLENGE)[2]:
                        break
                challenge = next((line[len(CHALLENGE):] for line in received.splitlines()
                                  if line.startswith(CHALLENGE)), None)
                assert challenge is not None, received
                details = json.loads(challenge)
                assert details["schema"] == "fvca-hypervisor-floor-challenge-v1"
                assert (details["approval_sha256"], details["previous_floor"], details["next_floor"]) == (digest, old, target)
                assert all(locked(path) for path in paths), "verification lost a lease before the TPM authorized the increment"
                message = bytes.fromhex(details["message"])
                assert len(message) == 108 and message[-40:] == reference.read_bytes()
                assert 0 < int.from_bytes(message[32:36], "big") <= 300
                expected = args.output / "command.hash"
                tool(socket, "tpm2_nvincrement", INDEX, "-C", INDEX, "--cphash", expected)
                assert expected.read_bytes() == b"\0\x20" + message[36:68]
                derivative = private.sign(message, ec.ECDSA(hashes.SHA256()))
                r, s = utils.decode_dss_signature(derivative)
                signature = bytes(64) if wrong_signature else r.to_bytes(32, "big") + s.to_bytes(32, "big")
                remainder, _ = client.communicate(signature.hex().encode("ascii") + b"\n", timeout=90)
                received.extend(remainder)
                if wrong_signature:
                    assert client.returncode and b"authorize the live session signature" in received, received
                    assert COMMITTED not in received and not intent.exists()
                else:
                    assert client.returncode == 0 and received.endswith(receipt), received
            finally:
                if client.poll() is None:
                    client.kill()
                    client.wait(timeout=10)
                (args.output / f"{name}.log").write_bytes(received)
        print(f"{name} passed", flush=True)

    with software_tpm(already) as socket:
        assert counter(socket, args.output) == target
        execute("missing-intent", socket, fail=b"already at the target floor without a matching durable intent")
    with software_tpm(working) as socket:
        assert counter(socket, args.output) == old
        wrong = args.output / "different-reference.bin"
        reference_bytes = reference.read_bytes()
        wrong.write_bytes(reference_bytes[:-1] + bytes([reference_bytes[-1] ^ 1]))
        execute("wrong-enrollment-reference", socket, fail=b"start a session for the enrolled increment authority",
                command=[*program[:-1], wrong])
        respond("wrong-session-signature", socket, wrong_signature=True)
        assert counter(socket, args.output) == old
        respond("increment-once", socket, wrong_signature=False)
        assert counter(socket, args.output) == target
        assert intent.read_bytes() == args.signature.read_bytes() + raw
        assert completed.read_bytes() == receipt
        completed.unlink()
        execute("recover-receipt", socket, expected=receipt)
        execute("idempotent-retry", socket, expected=receipt)
        assert counter(socket, args.output) == target and completed.read_bytes() == receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("client", "state", "approval", "signature", "authority", "certificate", "increment-key",
                 "enrollment", "output"):
        parser.add_argument(f"--{name}", type=lambda path: Path(path).absolute(), required=True)
    os.umask(0o077)
    qualify(parser.parse_args())
