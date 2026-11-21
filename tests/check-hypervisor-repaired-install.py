#!/usr/bin/env python3
"""Exercise both attended repair phases and their interruption boundaries."""

import argparse
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import runpy
import selectors
import subprocess
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tuf.api.metadata import TargetFile


HERE = Path(__file__).parent
gpt = runpy.run_path(HERE / "check-hypervisor-gpt-install.py")
tuf = runpy.run_path(HERE / "check-release-intake.py")
software_tpm = runpy.run_path(HERE / "check-standing-hypervisor-install.py")["software_tpm"]
INSTALLED = b"FVCA_HYPERVISOR_REPAIRED_SLOT_INSTALLED "
INVALIDATED = gpt["INVALIDATED"]


def qualify(args):
    source = args.fixture
    root = args.output
    root.mkdir(mode=0o700)
    state = root / "state"
    state.mkdir(mode=0o700)
    scratch = state / ".repaired-install"
    flags = root / "qualification.json"
    tuf["write_json"](flags, {"profile": "disposable repaired-slot installation"})
    depot = root / "depot"
    targets = depot / "targets"
    targets.mkdir(parents=True)
    config = root / "depot.json"
    tuf["write_json"](config, {"transport": "local", "path": str(depot)})
    signed = {}
    choices = {}
    for label, epoch in (("previous", 1), ("survivor", 2), ("replacement", 2)):
        choice, members = tuf["make_release"](root, {
            "boot.raw": source / f"boot-{label}.raw",
            "vm-runtime.raw": source / "vm-runtime.raw",
            "guest-boot.raw": source / "guest-boot.raw",
            "qualification.json": flags,
        }, epoch, "hypervisor")
        choices[label] = choice
        for path, member in members.items():
            descriptor = TargetFile.from_file(path, str(member), ["sha256"])
            os.link(member, targets / f"{descriptor.hashes['sha256']}.{path}")
            signed[path] = descriptor
    now = datetime.now(UTC).replace(microsecond=0)
    tuf["publish"](depot, (1, 1), tuf["new_keys"](), now, signed)
    for label, choice in choices.items():
        request = root / f"{label}-selection.json"
        tuf["write_json"](request, choice)
        subprocess.run([args.client, depot / "metadata/1.root.json", config, state, request],
                       check=True, capture_output=True, timeout=120)

    survivor, replacement = [
        gpt["clone"](source / f"{label}.raw", root / f"{label}.raw")
        for label in ("survivor", "replacement")
    ]
    disks = [survivor, replacement]
    regions = [gpt["partitions"](disk) for disk in disks]
    data = [gpt["digest"](disk, layout[gpt["DATA"]]) for disk, layout in zip(disks, regions, strict=True)]

    def inspect(disk):
        return json.loads(subprocess.check_output([args.client, "--inspect-hypervisor-gpt", disk, "4096"]))

    def released(label):
        return {key: choices[label][key] for key in ("epoch", "manifest_sha256")}

    def content(disk):
        return gpt["sparse_fingerprint"](disk)

    reviewed = list(map(inspect, disks))
    key = Ed25519PrivateKey.generate()
    authority = root / "authority.public"
    authority.write_bytes(key.public_key().public_bytes_raw())
    certificate = source / "boot.crt"
    stamp = int(now.timestamp())
    prepare = {
        "schema": "fvca-hypervisor-repaired-slot-v1", "phase": "prepare-replacement",
        "valid_from": stamp - 30, "expires": stamp + 1800, "sector_size": 4096,
        "secure_boot_certificate_sha256": hashlib.sha256(certificate.read_bytes()).hexdigest(),
        "epoch_policy_sha256": (source / "epoch-policy-fingerprint").read_text().strip(),
        "floor": 1, "unlock": (source / "unlock-profile").read_text().strip(),
        "storage_pcr_key_fingerprint": (source / "storage-pcr-fingerprint").read_text().strip(),
        "previous_storage_policy_sha256": (source / "previous-storage-policy-sha256").read_text().strip(),
        "repaired_storage_policy_sha256": (source / "repaired-storage-policy-sha256").read_text().strip(),
        "mirror_repair_evidence_sha256": "e" * 64,
        "previous_survivor": released("previous"),
        "survivor": {"disk": reviewed[0], "release": released("survivor")},
        "replacement": {"disk": reviewed[1], "release": released("replacement")},
    }
    # These fixture values exercise signed evidence fields. The storage boot
    # tests exercise actual unlock and recovery separately.
    complete = prepare | {"phase": "complete-pair", "replacement_boot_evidence_sha256": "f" * 64}

    def command(name, approval, *, tamper=False):
        doc = root / f"{name}.json"
        signature = root / f"{name}.sig"
        body = json.dumps(approval).encode("ascii") + b"\n"
        doc.write_bytes(body + (b" " if tamper else b""))
        signature.write_bytes(key.sign(body))
        return [args.client, "--install-repaired-hypervisor-slot", state, doc, signature, authority, certificate]

    def run(name, approval, env, *, refusal=None, tamper=False, unchanged=False):
        before = list(map(content, disks)) if refusal or unchanged else None
        job = subprocess.run(command(name, approval, tamper=tamper), env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
        out = job.stdout
        (root / f"{name}.log").write_bytes(out)
        if refusal:
            assert job.returncode and refusal in out and INVALIDATED not in out, out
        else:
            marker = INSTALLED + approval["phase"].encode("ascii") + b" "
            assert job.returncode == 0 and marker in out, out
            if unchanged:
                assert INVALIDATED not in out
        if before is not None:
            assert list(map(content, disks)) == before
        assert not scratch.exists()
        print(f"{name} passed", flush=True)

    def interrupt(name, approval, env, target):
        peer = 1 - target
        preserved = content(disks[peer])
        with subprocess.Popen(command(name, approval), env=env, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT) as job, selectors.DefaultSelector() as poll:
            log = bytearray()
            poll.register(job.stdout, selectors.EVENT_READ)
            until = time.monotonic() + 120
            try:
                while INVALIDATED not in log and poll.select(max(0, until - time.monotonic())):
                    chunk = os.read(job.stdout.fileno(), 65536)
                    if not chunk:
                        break
                    log.extend(chunk)
                assert INVALIDATED in log, log
                job.kill()
                log.extend(job.communicate(timeout=10)[0])
                assert job.returncode < 0 and INSTALLED not in log, log
            finally:
                if job.poll() is None:
                    job.kill()
                (root / f"{name}.log").write_bytes(log)
        assert content(disks[peer]) == preserved
        assert gpt["zeroed"](disks[target], regions[target]["fvca-esp"])
        (scratch / "interrupted-operation").touch(exist_ok=False)
        assert [gpt["digest"](disk, layout[gpt["DATA"]]) for disk, layout in zip(disks, regions, strict=True)] == data
        print(f"{name} left the peer and both data partitions intact", flush=True)

    with software_tpm(args.floor_two) as env:
        run("floor-changed", prepare, env, refusal=b"live TPM floor differs")
    with software_tpm(args.floor_one) as env:
        run("signature-required", prepare, env, tamper=True, refusal=b"approval signature is invalid")
        run("expired", prepare | {"valid_from": stamp - 300, "expires": stamp - 1}, env,
            refusal=b"outside its validity interval")
        run("separate-boot-evidence-required", complete | {"replacement_boot_evidence_sha256": None}, env,
            refusal=b"requires separate replacement boot evidence")
        run("replacement-readback-required", complete, env, refusal=b"mcopy refused")
        other_profile = "tpm2-pin" if prepare["unlock"] == "tpm2-auto" else "tpm2-auto"
        run("unlock-profile-pinned", prepare | {"unlock": other_profile}, env,
            refusal=b"PCR authorization")
        run("pcr-authority-pinned", prepare | {"storage_pcr_key_fingerprint": "d" * 64}, env,
            refusal=b"PCR authorization")
        run("replacement-storage-policy-pinned", prepare | {"repaired_storage_policy_sha256": "c" * 64}, env,
            refusal=b"signed Host storage enrollment differs")
        original = content(survivor)
        interrupt("interrupted-replacement", prepare, env, 1)
        run("install-replacement", prepare, env)
        run("repeat-replacement", prepare, env, unchanged=True)
        assert content(survivor) == original
        spare = content(replacement)
        interrupt("interrupted-survivor", complete, env, 0)
        run("install-survivor", complete, env)
        run("repeat-survivor", complete, env, unchanged=True)
        assert content(replacement) == spare
    assert list(map(inspect, disks)) == reviewed
    for disk, layout, label, original_data in zip(disks, regions, ("survivor", "replacement"), data, strict=True):
        artifact = source / f"boot-{label}.raw"
        for part, expected in gpt["partitions"](artifact).items():
            offset, capacity = layout[part]
            length = expected[1]
            assert gpt["digest"](disk, (offset, length)) == gpt["digest"](artifact, expected)
            assert gpt["zeroed"](disk, (offset + length, capacity - length))
        assert gpt["digest"](disk, layout[gpt["DATA"]]) == original_data
    print("both installed releases passed readback and both original data partitions were preserved", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("client", "fixture", "floor-one", "floor-two", "output"):
        parser.add_argument(f"--{name}", type=lambda path: Path(path).absolute(), required=True)
    os.umask(0o077)
    qualify(parser.parse_args())
