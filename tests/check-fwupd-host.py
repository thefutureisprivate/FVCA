#!/usr/bin/env python3
"""Check the packaged Host daemon and bus inside a disposable Fedora root."""

import argparse
from contextlib import contextmanager
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time


FWUPD = "org.freedesktop.fwupd"
DBUS = "org.freedesktop.DBus"
CONFIG = Path("/usr/lib/fvca/firmware-bus.conf")
MFD_NOEXEC_SEAL = 0x0008  # Linux memfd UAPI, not exposed by Python's os module.


@contextmanager
def running(command, **kwargs):
    process = subprocess.Popen(command, **kwargs)
    try:
        yield process
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


@contextmanager
def catalog_descriptor(content, *, sealed=True):
    fd = os.memfd_create("fwupd-catalog-test", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING | MFD_NOEXEC_SEAL)
    try:
        with os.fdopen(os.dup(fd), "wb") as stream:
            stream.write(content)
        os.lseek(fd, 0, os.SEEK_SET)
        if sealed:
            seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
        yield fd
    finally:
        os.close(fd)


def check_catalog(call, owner, metadata, signature):
    def receipt():
        return json.loads(call("get-property", owner, "/", FWUPD, "FvcaCatalog").stdout)["data"]

    assert receipt() == ""
    premature = call("call", owner, "/", FWUPD, "GetUpgrades", "s", "0" * 40, check=False)
    assert premature.returncode != 0 and "Access denied" in premature.stderr, premature.stderr
    changed = bytes([metadata[0] ^ 1]) + metadata[1:]
    identity = f"{sha256(metadata).hexdigest()}:{sha256(signature).hexdigest()}"

    with catalog_descriptor(signature) as jcat, catalog_descriptor(metadata) as content:
        def publish(data, remote="lvfs", **kwargs):
            return call("call", owner, "/", FWUPD, "UpdateMetadata", "shh", remote, str(data), str(jcat),
                        pass_fds=(data, jcat), **kwargs)

        foreign = publish(content, "lvfs-testing", check=False)
        assert foreign.returncode != 0 and "Access denied" in foreign.stderr, foreign.stderr
        with catalog_descriptor(metadata, sealed=False) as unsealed:
            rejected = publish(unsealed, check=False)
        assert rejected.returncode != 0 and "sealed, non-executable" in rejected.stderr, rejected.stderr
        with catalog_descriptor(changed) as corrupt:
            rejected = publish(corrupt, check=False)
        assert rejected.returncode != 0 and "checksum" in rejected.stderr.lower(), rejected.stderr
        assert receipt() == ""
        publish(content)
        assert receipt() == f"1:{identity}"
        publish(content)
        assert receipt() == f"2:{identity}"
    print("fwupd verifies the LVFS signature and binds catalog generations to the exact bytes")


def check(directory, metadata, signature):
    address = f"unix:path={directory / 'bus'}"

    def call(*args, check=True, **kwargs):
        return subprocess.run(
            ["busctl", f"--address={address}", "--json=short", "--timeout=30", *args],
            check=check, timeout=32, capture_output=True, text=True, **kwargs,
        )

    launcher = [
        "systemd-socket-activate", f"--listen={directory / 'bus'}", "/usr/bin/dbus-daemon",
        f"--config-file={CONFIG}", "--nofork", "--nopidfile",
    ]
    ready = directory / "ready"
    (directory / "state").mkdir(mode=0o700)
    (directory / "cache").mkdir(mode=0o700)
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notify, running(launcher) as bus:
        notify.bind(str(ready))
        notify.settimeout(20)
        deadline = time.monotonic() + 4
        while not (directory / "bus").exists():
            if bus.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("private firmware socket did not start")
            time.sleep(0.01)
        with running(
            ["/usr/libexec/fwupd/fwupd"],
            env={
                **os.environ,
                "DBUS_SYSTEM_BUS_ADDRESS": address,
                "NOTIFY_SOCKET": str(ready),
                "STATE_DIRECTORY": str(directory / "state"),
                "CACHE_DIRECTORY": str(directory / "cache"),
            },
        ) as daemon:
            assert notify.recv(4096) == b"READY=1"
            assert "/usr/lib64/fvca/libhardened_malloc.so" in Path(f"/proc/{daemon.pid}/maps").read_text()
            well_known = call("call", DBUS, "/org/freedesktop/DBus", DBUS, "GetNameOwner", "s", FWUPD)
            owner, = json.loads(well_known.stdout)["data"]
            pid = call("call", DBUS, "/org/freedesktop/DBus", DBUS, "GetConnectionUnixProcessID", "s", owner)
            assert json.loads(pid.stdout)["data"] == [daemon.pid]
            trusted = call("get-property", owner, "/", FWUPD, "OnlyTrusted")
            assert json.loads(trusted.stdout) == {"type": "b", "data": True}
            plugins = call("call", owner, "/", FWUPD, "GetPlugins")
            inventory, = json.loads(plugins.stdout)["data"]
            assert sorted(plugin["Name"]["data"] for plugin in inventory) == ["nvme", "uefi_capsule"]
            print("real fwupd peer is ready and has exactly the two built-in plugins")
            check_catalog(call, owner, metadata, signature)

            # Exercise both the real well-known-name policy and the unique-name path used by Rust.
            for peer in (FWUPD, owner):
                for interface, method in ((FWUPD, "Install"), (FWUPD, "ModifyConfig"), (FWUPD, "Quit"),
                                          (f"{DBUS}.Properties", "Set")):
                    try:
                        subprocess.run(
                            ["dbus-send", f"--bus={address}", "--print-reply", "--reply-timeout=4000",
                             f"--dest={peer}", "/", f"{interface}.{method}"],
                            check=True, timeout=5, capture_output=True, text=True,
                        )
                    except subprocess.CalledProcessError as error:
                        assert "Rejected send message" in error.stderr, error.stderr
                    else:
                        raise RuntimeError(f"private bus allowed {method}")
            print("the private bus rejects install, configuration changes and daemon shutdown")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", required=True, type=Path)
    parser.add_argument("--signature", required=True, type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0 or not CONFIG.is_file():
        raise SystemExit("run inside a disposable Fedora root with the staged firmware component")
    with tempfile.TemporaryDirectory(prefix="fvca-fwupd-host-") as path:
        check(Path(path), args.catalog.read_bytes(), args.signature.read_bytes())
