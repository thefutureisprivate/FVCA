#!/usr/bin/env python3
"""Exercise TUF-authorized writes against disposable Hypervisor GPT disk copies."""

import argparse
from datetime import UTC, datetime
import errno
import hashlib
import json
import os
from pathlib import Path
import runpy
import selectors
import subprocess
import time

from tuf.api.metadata import TargetFile


SECTOR = 4096
CHUNK = 1024 * 1024
DATA = "fvca-host_data"
INSTALLED = b"FVCA_HYPERVISOR_SLOT_INSTALLED "
INVALIDATED = b"FVCA_HYPERVISOR_ESP_INVALIDATED "


def clone(source, dest):
    subprocess.run(["cp", "--reflink=auto", "--sparse=always", "--", source, dest], check=True)
    dest.chmod(0o600)
    return dest


def partitions(disk):
    table = json.loads(subprocess.check_output(["sfdisk", "--json", "--sector-size", str(SECTOR), disk]))
    return {part["name"]: (part["start"] * SECTOR, part["size"] * SECTOR)
            for part in table["partitiontable"]["partitions"]}


def span(stream, start, length):
    stream.seek(start)
    while length:
        data = stream.read(min(length, CHUNK))
        assert data
        yield data
        length -= len(data)


def digest(disk, extent):
    value = hashlib.sha256()
    with disk.open("rb") as stream:
        for chunk in span(stream, *extent):
            value.update(chunk)
    return value.digest()


def zeroed(disk, extent):
    with disk.open("rb") as stream:
        return all(chunk.count(0) == len(chunk) for chunk in span(stream, *extent))


def sparse_fingerprint(disk):
    """Read all recorded extents to compare an entire sparse recovery disk."""
    value = hashlib.sha256()
    size = disk.stat().st_size
    value.update(size.to_bytes(8, "little"))
    with disk.open("rb", buffering=0) as stream:
        offset = 0
        while offset < size:
            try:
                start = os.lseek(stream.fileno(), offset, os.SEEK_DATA)
            except OSError as error:
                if error.errno != errno.ENXIO:
                    raise
                break
            offset = os.lseek(stream.fileno(), start, os.SEEK_HOLE)
            for number in (start, offset):
                value.update(number.to_bytes(8, "little"))
            for chunk in span(stream, start, offset - start):
                value.update(chunk)
    return value.digest()


def qualify(args):
    tuf = runpy.run_path(Path(__file__).with_name("check-release-intake.py"))
    root = args.output
    root.mkdir(mode=0o700)
    active = clone(args.active, root / "active.raw")
    inactive = clone(args.inactive, root / "inactive.raw")
    active_initial = sparse_fingerprint(active)
    inactive_regions = partitions(inactive)
    unchanged_data = digest(inactive, inactive_regions[DATA])
    depot = root / "depot"
    targets = depot / "targets"
    targets.mkdir(parents=True)
    cache = root / "cache"
    cache.mkdir(mode=0o700)
    config = root / "depot.json"
    qualification = root / "qualification.json"
    tuf["write_json"](config, {"transport": "local", "path": str(depot)})
    tuf["write_json"](qualification, {"profile": "disposable offline GPT installation"})
    signed = {}
    choices = {}
    for label, epoch, slot, runtime in (
        ("active", 17, args.active_boot, args.active_runtime),
        ("next", 18, args.next_boot, args.next_runtime),
        ("mixed", 19, args.next_boot, args.wrong_runtime),
    ):
        selection, sources = tuf["make_release"](root, {
            "boot.raw": slot, "vm-runtime.raw": runtime, "guest-boot.raw": args.guest,
            "qualification.json": qualification,
        }, epoch, "hypervisor")
        choices[label] = selection | {"minimum_epoch": 17}
        for logical, source in sources.items():
            member = TargetFile.from_file(logical, str(source), ["sha256"])
            os.link(source, targets / f"{member.hashes['sha256']}.{logical}")
            signed[logical] = member
    tuf["publish"](depot, (1, 1), tuf["new_keys"](), datetime.now(UTC).replace(microsecond=0), signed)
    trusted = depot / "metadata/1.root.json"

    def command(name, choice, plan=None):
        selection = root / f"{name}-selection.json"
        tuf["write_json"](selection, choices[choice])
        argv = [args.client, trusted, config, cache, selection]
        if plan is not None:
            reference = root / f"{name}-plan.json"
            tuf["write_json"](reference, plan)
            argv += ["--write-inactive-gpt", reference]
        return argv

    def run(name, choice, plan=None, *, refusal=None):
        result = subprocess.run(command(name, choice, plan), stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, umask=0o022, timeout=120)
        (root / f"{name}.log").write_bytes(result.stdout)
        if refusal is not None:
            assert result.returncode and refusal in result.stdout and INVALIDATED not in result.stdout, result.stdout
        else:
            expected = b"FVCA_RELEASE_STAGED " if plan is None else INSTALLED
            assert result.returncode == 0 and expected in result.stdout, result.stdout
        print(f"{name} passed", flush=True)
        return result.stdout

    def inspect(disk):
        return json.loads(subprocess.check_output([args.client, "--inspect-hypervisor-gpt", disk, str(SECTOR)]))

    run("stage-recovery", "active")
    review = {"schema": "fvca-hypervisor-gpt-install-v1", "sector_size": SECTOR,
              "boot_certificate": str(args.boot_certificate), "active_epoch": 17,
              "active_manifest_sha256": choices["active"]["manifest_sha256"],
              "active": inspect(active), "inactive": inspect(inactive)}
    initial_candidate = sparse_fingerprint(inactive)

    altered = clone(inactive, root / "relabeled.raw")
    subprocess.run(["sfdisk", "--sector-size", str(SECTOR), "--part-label", altered, "8", "rejected-data"],
                   stdout=subprocess.DEVNULL, check=True)
    run("changed-gpt", "next", review | {"inactive": review["inactive"] | {"path": str(altered)}},
        refusal=b"GPT differs from the reviewed disk fingerprint")
    run("mixed-runtime", "mixed", review, refusal=b"packed Hypervisor slot differs")
    broken = clone(active, root / "damaged-recovery.raw")
    with broken.open("r+b") as stream:
        stream.seek(partitions(active)["fvca-core"][0])
        byte = stream.read(1)
        stream.seek(-1, os.SEEK_CUR)
        stream.write(bytes([byte[0] ^ 1]))
    run("damaged-recovery", "next", review | {"active": review["active"] | {"path": str(broken)}},
        refusal=b"active recovery payload differs")
    assert sparse_fingerprint(inactive) == initial_candidate

    with subprocess.Popen(command("interrupt", "next", review), stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, umask=0o022) as child, selectors.DefaultSelector() as poll:
        log = bytearray()
        poll.register(child.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + 120
        try:
            while INVALIDATED not in log and poll.select(max(0, deadline - time.monotonic())):
                data = os.read(child.stdout.fileno(), 65536)
                if not data:
                    break
                log.extend(data)
            assert INVALIDATED in log, log
            child.kill()
            remainder, _ = child.communicate(timeout=15)
            log.extend(remainder)
            assert child.returncode < 0 and INSTALLED not in log, log
        finally:
            if child.poll() is None:
                child.kill()
        (root / "interrupt.log").write_bytes(log)
    assert inspect(inactive) == review["inactive"]
    assert digest(inactive, inactive_regions[DATA]) == unchanged_data
    assert zeroed(inactive, inactive_regions["fvca-esp"])
    assert sparse_fingerprint(active) == active_initial
    clone(inactive, root / "interrupted.raw")
    print("interruption left the recovery disk and encrypted member intact with inactive EFI cleared", flush=True)

    run("install-after-interruption", "next", review)
    approved = partitions(args.next_boot)
    assert set(approved) == inactive_regions.keys() - {DATA}
    assert any(inactive_regions[name][1] > extent[1] for name, extent in approved.items())
    for name, extent in approved.items():
        start, capacity = inactive_regions[name]
        length = extent[1]
        assert digest(inactive, (start, length)) == digest(args.next_boot, extent)
        assert zeroed(inactive, (start + length, capacity - length))
    on_disk = inactive.stat()
    assert INVALIDATED not in run("identical-retry", "next", review)
    assert inactive.stat().st_mtime_ns == on_disk.st_mtime_ns
    assert inspect(inactive) == review["inactive"]
    assert digest(inactive, inactive_regions[DATA]) == unchanged_data
    assert sparse_fingerprint(active) == active_initial
    print("both GPTs, the recovery disk, and the full encrypted data member were preserved", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("client", "active", "inactive", "active-boot", "next-boot", "active-runtime", "next-runtime",
                 "wrong-runtime", "guest", "boot-certificate", "output"):
        parser.add_argument(f"--{name}", type=lambda path: Path(path).absolute(), required=True)
    os.umask(0o077)
    qualify(parser.parse_args())


if __name__ == "__main__":
    main()
