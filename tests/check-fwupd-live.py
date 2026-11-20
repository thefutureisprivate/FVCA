#!/usr/bin/env python3
"""Exercise the fwupd wire adapter on a disposable D-Bus instance."""

import argparse
from contextlib import contextmanager
import fcntl
from hashlib import sha256
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
from xml.sax.saxutils import escape


def serve(address, mode):
    import dbus
    import dbus.service
    from dbus.mainloop.glib import DBusGMainLoop
    from gi.repository import GLib

    interface = "org.freedesktop.fwupd"
    device_id = "a" * 40

    class Fwupd(dbus.service.Object):
        catalog = ""

        @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="ss", out_signature="v")
        def Get(self, name, prop):
            assert name == interface
            setting = mode.read_text()
            return {
                "OnlyTrusted": dbus.Boolean(setting != "untrusted"),
                "Tainted": dbus.Boolean(setting == "tainted"),
                "DaemonVersion": dbus.String("2.0.20"),
                "FvcaCatalog": dbus.String(
                    self.catalog.replace("1:", "2:", 1) if setting == "catalog-replaced" else self.catalog
                ),
            }[prop]

        @dbus.service.method(interface, in_signature="shh", out_signature="")
        def UpdateMetadata(self, remote, metadata, signature):
            assert remote == "lvfs"
            digests = []
            for descriptor in (metadata, signature):
                with os.fdopen(descriptor.take(), "rb") as stream:
                    seals = fcntl.fcntl(stream, fcntl.F_GET_SEALS)
                    required = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
                    assert seals & required == required
                    assert not os.fstat(stream.fileno()).st_mode & 0o111
                    digests.append(sha256(stream.read()).hexdigest())
            self.catalog = "1:" + ":".join(digests)

        @dbus.service.method(interface, in_signature="ssssssssuuh", out_signature="tb")
        def VerifyFvcaCabinet(self, selected, archive, payload, guid, protocol, before, after,
                              version_format, raw_before, raw_after, fd):
            assert selected == device_id
            assert payload == "7" * 64
            assert guid == "a1234567-d234-4031-a111-000000000000"
            assert (protocol, before, after, version_format, raw_before, raw_after) == (
                "org.uefi.capsule", "1.42", "1.51", "pair", 65578, 65587,
            )
            with os.fdopen(fd.take(), "rb") as stream:
                seals = fcntl.fcntl(stream, fcntl.F_GET_SEALS)
                required = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
                assert seals & required == required
                assert not os.fstat(stream.fileno()).st_mode & 0o111
                content = stream.read()
                assert content == b"exact cabinet" and archive == sha256(content).hexdigest()
            return dbus.UInt64(16_908_288), dbus.Boolean(mode.read_text() != "other-capsule-backend")

        @dbus.service.method(interface, in_signature="ssssssssssuuhh", out_signature="")
        def StageFvcaCapsule(self, selected, archive, payload, guid, protocol, before, after,
                             version_format, transaction, offer_sha256, raw_before, raw_after,
                             cabinet, lease):
            with os.fdopen(lease.take(), "rb") as inherited:
                if mode.read_text() == "policy":
                    os.close(cabinet.take())
                    return
                assert transaction == "f1234567-d234-4031-a111-000000000000"
                assert offer_sha256 == "b" * 64
                self.VerifyFvcaCabinet(selected, archive, payload, guid, protocol, before, after,
                                       version_format, raw_before, raw_after, cabinet)
                with mode.with_suffix(".lease").open("rb") as independent:
                    assert os.path.samestat(os.fstat(inherited.fileno()), os.fstat(independent.fileno()))
                    try:
                        fcntl.flock(independent, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        pass
                    else:
                        raise AssertionError("lifecycle lease was unlocked")
                    fcntl.flock(inherited, fcntl.LOCK_EX | fcntl.LOCK_NB)

        @dbus.service.method(interface, in_signature="", out_signature="aa{sv}")
        def GetDevices(self):
            setting = mode.read_text()
            device = {
                "DeviceId": device_id,
                "Guid": dbus.Array(["a1234567-d234-4031-a111-000000000000"], signature="s"),
                "Plugin": "uefi_capsule",
                "Name": "x" * 4097 if setting == "oversized" else "Fixture BIOS",
                "Protocol": "org.uefi.capsule",
                "VendorId": "DMI:Fixture|UEFI:Fixture",
                "Flags": "wrong" if setting == "wrong-type" else dbus.UInt64(259),
                "Problems": dbus.UInt64(0),
                "Version": "1.42",
                "VersionFormat": dbus.UInt32(3),
                "VersionRaw": dbus.UInt64(65578),
                "Created": dbus.UInt64(42),
            }
            if setting.startswith("post-update"):
                device["Name"] = "System Firmware"
                device["Flags"] = dbus.UInt64(1)
                device["Version"] = "1.51"
                device["VersionRaw"] = dbus.UInt64(65587)
            return [device, device] if setting == "duplicate" else [device]

        @dbus.service.method(interface, in_signature="sss", out_signature="ssu")
        def GetFvcaResult(self, device, transaction, offer_sha256):
            assert device == device_id
            assert transaction == "f1234567-d234-4031-a111-000000000000"
            assert offer_sha256 == "b" * 64
            setting = mode.read_text()
            return (
                "1.52" if setting == "post-update-other-release" else "1.51",
                "org.uefi.capsule",
                dbus.UInt32(3 if setting == "post-update-conflict" else 2),
            )

        @dbus.service.method(interface, in_signature="s", out_signature="aa{sv}")
        def GetUpgrades(self, device):
            assert device == device_id
            assert mode.read_text() != "post-update"
            return [{
                "Version": "1.51",
                "RemoteId": "lvfs",
                "Protocol": "org.uefi.capsule",
                "Checksum": "8" * 40 + "," + "7" * 64,
                "TrustFlags": dbus.UInt64(262),
            }]

    DBusGMainLoop(set_as_default=True)
    connection = dbus.bus.BusConnection(address)
    name = dbus.service.BusName(interface, bus=connection, do_not_queue=True)
    service = Fwupd(name, "/")
    print("ready", flush=True)
    GLib.MainLoop().run()
    service.remove_from_connection()


@contextmanager
def running(command):
    process = subprocess.Popen(command, text=True, stdout=subprocess.PIPE)
    try:
        if not select.select([process.stdout], [], [], 10)[0]:
            raise TimeoutError(f"{command[0]} did not report readiness")
        ready = process.stdout.readline().strip()
        if not ready:
            raise RuntimeError(f"{command[0]} exited before it was ready")
        yield process, ready
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        process.stdout.close()


def check(daemon, binary):
    with tempfile.TemporaryDirectory(prefix="fvca-fwupd-") as path:
        directory = Path(path)
        config = directory / "bus.conf"
        config.write_text(f"""<busconfig>
  <type>session</type>
  <listen>unix:path={escape(str(directory / 'bus'))}</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*"/>
    <allow receive_sender="*"/>
    <allow own="org.freedesktop.fwupd"/>
  </policy>
  <limit name="max_message_size">1048576</limit>
</busconfig>""")
        mode = directory / "mode"
        mode.write_text("normal")
        with running([daemon, f"--config-file={config}", "--nofork", "--print-address=1"]) as (_, address):
            command = [sys.executable, __file__, "--serve", address, str(mode)]
            with running(command) as (service, ready):
                if ready != "ready":
                    raise RuntimeError("unexpected fwupd fixture readiness message")
                subprocess.run(
                    [binary, "--ignored", "--exact", "firmware::live::tests::reads_only_the_pinned_fwupd_peer"],
                    check=True,
                    env={
                        **os.environ,
                        "FVCA_TEST_FWUPD_ADDRESS": address,
                        "FVCA_TEST_FWUPD_EXECUTABLE": os.readlink(f"/proc/{service.pid}/exe"),
                        "FVCA_TEST_FWUPD_MODE": str(mode),
                    },
                    timeout=45,
                )


def check_packaged_policy(daemon, policies):
    import dbus
    from dbus.lowlevel import MethodCallMessage
    from dbus.types import UnixFd

    interface = "org.freedesktop.fwupd"
    with tempfile.TemporaryDirectory(prefix="fvca-fwupd-policy-") as path:
        directory = Path(path)
        common = (policies / "firmware-bus-common.conf").read_text()
        for endpoint in ("inventory", "writer"):
            socket = directory / f"{endpoint}-bus"
            (directory / "firmware-bus-common.conf").write_text(
                common.replace("systemd:", f"unix:path={escape(str(socket))}", 1)
            )
            config = directory / f"firmware-bus-{endpoint}.conf"
            config.write_bytes((policies / config.name).read_bytes())
            mode = directory / "mode"
            mode.write_text("policy")
            with running([daemon, f"--config-file={config}", "--nofork", "--print-address=1"]) as (_, address):
                with running([sys.executable, __file__, "--serve", address, str(mode)]) as (_, ready):
                    assert ready == "ready"
                    peer = dbus.bus.BusConnection(address)
                    try:
                        owner = peer.get_name_owner(interface)
                        device = "a" * 40
                        operation = (device, "f1234567-d234-4031-a111-000000000000", "b" * 64)
                        stage = ("",) * 8 + operation[1:] + (dbus.UInt32(0), dbus.UInt32(0))
                        signature = "ssssssssssuu"
                        with open(os.devnull, "rb") as harmless:
                            fds = (UnixFd(harmless.fileno()), UnixFd(harmless.fileno()))
                            for destination in (interface, owner):
                                for method, wire, args, allowed in (
                                    ("StageFvcaCapsule", signature + "hh", stage + fds, endpoint == "writer"),
                                    ("StageFvcaCapsule", signature + "h", stage + fds[:1], False),
                                    ("StageFvcaCapsule", signature, stage, False),
                                    ("GetDevices", "", (), True),
                                    ("GetUpgrades", "s", (device,), True),
                                    ("GetFvcaResult", "sss", operation, endpoint == "inventory"),
                                    ("Install", "", (), False),
                                    ("Quit", "", (), False),
                                ):
                                    message = MethodCallMessage(destination, "/", interface, method)
                                    message.append(*args, signature=wire)
                                    try:
                                        peer.send_message_with_reply_and_block(message, 3)
                                    except dbus.DBusException as error:
                                        assert not allowed and error.get_dbus_name() == "org.freedesktop.DBus.Error.AccessDenied", error
                                    else:
                                        assert allowed, (endpoint, destination, method, wire)
                    finally:
                        peer.close()
    print("FVCA_FWUPD_INVENTORY_AND_WRITER_BUS_POLICIES_ARE_DISTINCT")


if __name__ == "__main__":
    if sys.argv[1:2] == ["--serve"]:
        serve(sys.argv[2], Path(sys.argv[3]))
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--dbus-daemon", default="dbus-daemon")
        parser.add_argument("--test-binary", required=True)
        parser.add_argument("--policy-directory", type=Path)
        arguments = parser.parse_args()
        check(arguments.dbus_daemon, arguments.test_binary)
        if arguments.policy_directory is not None:
            check_packaged_policy(arguments.dbus_daemon, arguments.policy_directory)
