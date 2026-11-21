#!/usr/bin/env python3
"""Check the fixed uutils invocations used by FVCA."""

import argparse
import hashlib
from pathlib import Path
import subprocess
import tempfile


def run(binary, *args, data=None, cwd=None):
    return subprocess.run([binary, *args], input=data, cwd=cwd, env={},
                          capture_output=True, timeout=15)


def qualify(binaries, work, hypervisor):
    names = ("echo", "sha256sum", "true", "chcon", "cp") if hypervisor else ("echo", "sha256sum", "true")
    for name in names:
        binary = binaries / name
        info = run(binary, "--version")
        assert not binary.is_symlink() and info.returncode == 0
        assert info.stdout.splitlines()[0] == f"{name} (uutils coreutils) 0.13.0".encode()
    for marker in (b"FVCA_DEV_BASE_READY", b"FVCA_BOOT_FAILED"):
        result = run(binaries / "echo", marker)
        assert not result.returncode and result.stdout == marker + b"\n"
    assert run(binaries / "true").returncode == 0

    payload = b"FVCA checksum qualification\n"
    digest = hashlib.sha256(payload).hexdigest().encode()
    checksum = binaries / "sha256sum"
    result = run(checksum, data=payload)
    assert not result.returncode and result.stdout == digest + b"  -\n"
    member = work / "data.raw"
    member.write_bytes(payload)
    record = digest + b"  data.raw\n"
    options = ("--strict", "--check", "--status", "-")
    for data, accepted in ((record, True), (b"0" * 64 + record[64:], False), (record + b"invalid\n", False)):
        result = run(checksum, *options, data=data, cwd=work)
        assert (result.returncode == 0) == accepted and not result.stdout

    if hypervisor:
        # A large hole and a byte-oriented filename match the capture escrow's file contract.
        source = work / "guest-\udcff.raw"
        destination = work / ".member.tmp"
        with source.open("wb") as output:
            output.write(payload)
            output.seek(8 * 1024 * 1024)
            output.write(payload)
        source.chmod(0o400)
        copy = binaries / "cp"
        options = ("--sparse=always", "--reflink=never", "--no-target-directory", "--")
        result = run(copy, *options, source, destination)
        assert result.returncode == 0, result.stderr
        assert destination.read_bytes() == source.read_bytes()
        assert destination.stat().st_blocks * 512 < destination.stat().st_size // 2
        assert run(copy, *options, source, work).returncode != 0
        assert run(copy, *options, work / "absent", destination).returncode != 0
    print("FVCA fixed uutils invocations passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=lambda path: Path(path).absolute())
    parser.add_argument("--hypervisor", action="store_true")
    options = parser.parse_args()
    with tempfile.TemporaryDirectory() as work:
        qualify(options.directory, Path(work), options.hypervisor)


if __name__ == "__main__":
    main()
