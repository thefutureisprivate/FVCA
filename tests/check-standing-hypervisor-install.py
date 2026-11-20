#!/usr/bin/env python3
"""Exercise standing-policy offline GPT preparation with disposable TPM and disk copies."""

import argparse
from contextlib import contextmanager
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import runpy
import selectors
import shutil
import subprocess
import tempfile
import time

from securesystemslib.signer import CryptoSigner
from tuf.api.metadata import TargetFile


HERE = Path(__file__).parent
tuf = runpy.run_path(HERE / "check-release-intake.py")
gpt = runpy.run_path(HERE / "check-hypervisor-gpt-install.py")
channel = runpy.run_path(HERE / "check-release-channel.py")


@contextmanager
def software_tpm(source):
    with tempfile.TemporaryDirectory(prefix="fvca-install-tpm-") as work:
        root = Path(work)
        shutil.copytree(source, root / "state")
        socket = root / "tpm.sock"
        argv = ["swtpm", "socket", "--tpm2", "--tpmstate", f"dir={root / 'state'}",
                "--server", f"type=unixio,path={socket}", "--ctrl", f"type=unixio,path={socket}.ctrl",
                "--flags", "not-need-init,startup-clear"]
        with subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as emulator:
            try:
                deadline = time.monotonic() + 5
                while not socket.exists() and emulator.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.05)
                assert socket.is_socket(), "TPM fixture did not start"
                yield os.environ | {"FVCA_TEST_SWTPM_SOCKET": str(socket)}
            finally:
                emulator.terminate()
                emulator.wait(timeout=10)


def qualify(args):
    root = args.output
    root.mkdir(mode=0o700)
    original = args.fixture
    active = gpt["clone"](original / "installed-a.raw", root / "active.raw")
    inactive = gpt["clone"](original / "installed-b.raw", root / "inactive.raw")
    stable = gpt["sparse_fingerprint"](active)
    regions = gpt["partitions"](inactive)
    before = gpt["digest"](inactive, regions["fvca-host_data"])
    with inactive.open("r+b") as disk:
        offset = regions["fvca-core"][0]
        disk.seek(offset)
        byte = disk.read(1)
        disk.seek(offset)
        disk.write(bytes([byte[0] ^ 1]))
    original_inactive = gpt["sparse_fingerprint"](inactive)
    cache = root / "state"
    cache.mkdir(mode=0o700)
    depot = root / "depot"
    files = depot / "targets"
    files.mkdir(parents=True)
    config = root / "depot.json"
    config_digest = tuf["write_json"](config, {"transport": "local", "path": str(depot)})
    qualifier = root / "qualification.json"
    tuf["write_json"](qualifier, {"profile": "disposable PIN-less GPT installation"})
    owner, approval = (CryptoSigner.generate_ed25519() for _ in range(2))
    public = root / "owner.public"
    public.write_bytes(bytes.fromhex(owner.public_key.keyval["public"]))
    roles = tuf["new_keys"]()
    now = datetime.now(UTC).replace(microsecond=0)
    stamp = int(now.timestamp())
    compatibility = "a" * 64
    resolutions = {}
    sources = {}
    for epoch, label in enumerate(("a", "b"), 1):
        choice, contents = tuf["make_release"](root, {
            "boot.raw": original / f"boot-{label}.raw", "qualification.json": qualifier,
            "vm-runtime.raw": original / "vm-runtime.raw", "guest-boot.raw": original / "guest-boot.raw",
        }, epoch, "hypervisor")
        resolutions[label] = choice
        sources.update(contents)
    candidate = resolutions["b"]["manifest_sha256"]
    pointer = root / "fvca-os-hypervisor-stable.json"
    sig = channel["signed"](pointer, {
        "schema": "fvca-os-channel-v1", "role": "hypervisor", "channel": "stable", "sequence": 2,
        "valid_from": stamp - 60, "expires": stamp + 1800, "compatibility_sha256": compatibility,
        "release": {"epoch": 2, "manifest_sha256": candidate,
                    "activation": {"urgency": "security", "activate_by": stamp + 900}},
    }, approval)
    sources |= {pointer.name: pointer, sig.name: sig}
    targets = {}
    for name, path in sources.items():
        target = TargetFile.from_file(name, str(path), ["sha256"])
        os.link(path, files / f"{target.hashes['sha256']}.{name}")
        targets[name] = target
    tuf["publish"](depot, (1, 1), roles, now, targets)
    trusted = depot / "metadata/1.root.json"
    request = root / "stable-selection.json"
    tuf["write_json"](request, resolutions["a"])
    subprocess.run([args.client, trusted, config, cache, request], check=True, capture_output=True, timeout=90)
    booted = {"role": "hypervisor", "slot": "a", "epoch": 1, "sequence": 1,
              "manifest_sha256": resolutions["a"]["manifest_sha256"]}
    active_record = cache / "active-os-release.json"
    tuf["write_json"](active_record, booted)

    def inspect(image):
        return json.loads(subprocess.check_output([args.client, "--inspect-hypervisor-gpt", image, "4096"]))

    disk_policy = {
        "sector_size": 4096, "boot_certificate": str(args.certificate),
        "boot_certificate_sha256": tuf["sha256"](args.certificate),
        "epoch_policy_sha256": (original / "epoch-policy-fingerprint").read_text().strip(),
        "storage_pcr_key_fingerprint": (original / "storage-pcr-fingerprint").read_text().strip(),
        "a": inspect(active), "b": inspect(inactive),
    }
    budget = sum(choice["max_release_bytes"] for choice in resolutions.values())
    policy = {
        "schema": "fvca-os-update-policy-v1", "revision": 1, "role": "hypervisor", "channel": "stable",
        "enabled": True, "valid_from": stamp - 60, "expires": stamp + 1800, "minimum_epoch": 1,
        "tuf_root_sha256": tuf["sha256"](trusted), "depot_config_sha256": config_digest,
        "qualification_key_ed25519": approval.public_key.keyval["public"], "compatibility_sha256": compatibility,
        "max_release_bytes": max(item["max_release_bytes"] for item in resolutions.values()), "max_staged_bytes": budget,
        "hypervisor_gpt": disk_policy,
    }
    policy_file = root / "policy.json"

    def command(settings):
        proof = channel["signed"](policy_file, settings, owner)
        return [args.client, "--discover-os-release", trusted, config, cache, policy_file, proof, public,
                "--prepare-inactive-gpt"]

    def run(label, settings, env, *, refusal=None):
        result = subprocess.run(command(settings), env=env, capture_output=True, timeout=130, check=False)
        log = result.stderr + result.stdout
        (root / f"{label}.log").write_bytes(log)
        if refusal is not None:
            assert result.returncode and refusal in log and gpt["INVALIDATED"] not in log, log
            return None
        assert result.returncode == 0, log
        return json.loads(result.stdout)

    hold = {"manifest_sha256": candidate, "until": stamp + 600}
    status = run("hold", policy | {"hold": hold}, os.environ)
    assert status["disposition"] == "hold" and status["prepared_inactive_slot"] is None
    live = policy | {"revision": 2}
    with software_tpm(args.floor_two) as env:
        run("floor-refusal", live, env, refusal=b"below the live TPM floor")
    assert gpt["sparse_fingerprint"](inactive) == original_inactive
    with software_tpm(args.floor_one) as env:
        wrong = disk_policy | {"storage_pcr_key_fingerprint": "b" * 64}
        run("pcr-authority-refusal", live | {"revision": 3, "hypervisor_gpt": wrong}, env,
            refusal=b"lacks the enrolled PIN-less PCR authorization")
    assert gpt["sparse_fingerprint"](inactive) == original_inactive
    live = live | {"revision": 4}

    with software_tpm(args.floor_one) as env, selectors.DefaultSelector() as poll, subprocess.Popen(
        command(live), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    ) as child:
        log = bytearray()
        poll.register(child.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + 120
        try:
            while gpt["INVALIDATED"] not in log and poll.select(max(0, deadline - time.monotonic())):
                data = os.read(child.stdout.fileno(), 65536)
                if not data:
                    break
                log.extend(data)
            assert gpt["INVALIDATED"] in log, log
        finally:
            child.kill()
            log.extend(child.communicate(timeout=15)[0])
        (root / "interrupted.log").write_bytes(log)
        assert child.returncode < 0 and gpt["INSTALLED"] not in log, log
    assert gpt["zeroed"](inactive, regions["fvca-esp"])
    assert gpt["sparse_fingerprint"](active) == stable
    assert gpt["digest"](inactive, regions["fvca-host_data"]) == before
    print("hold, live floor, PIN-less authority and interrupted ESP publication passed", flush=True)

    with software_tpm(args.floor_one) as env:
        status = run("installed", live, env)
        assert status["prepared_inactive_slot"] == "b" and status["active"] == booted
        unchanged = inactive.stat().st_mtime_ns
        assert run("identical-retry", live, env)["prepared_inactive_slot"] == "b"
        assert inactive.stat().st_mtime_ns == unchanged
    for name, extent in gpt["partitions"](original / "boot-b.raw").items():
        assert gpt["digest"](inactive, (regions[name][0], extent[1])) == gpt["digest"](original / "boot-b.raw", extent)
    assert json.loads(active_record.read_text()) == booted
    assert gpt["sparse_fingerprint"](active) == stable
    assert gpt["digest"](inactive, regions["fvca-host_data"]) == before
    assert inspect(inactive) == disk_policy["b"]
    print("standing policy prepared only the inactive slot and verified a write-free retry", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("client", "fixture", "certificate", "floor-one", "floor-two", "output"):
        parser.add_argument(f"--{name}", type=lambda value: Path(value).absolute(), required=True)
    os.umask(0o077)
    qualify(parser.parse_args())
