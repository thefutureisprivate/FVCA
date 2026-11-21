#!/usr/bin/env python3
"""Qualify permit expiry and HTTPS revocation in an enrolled KVM Guest."""

import argparse
from datetime import UTC, datetime
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
import tempfile

from tuf.api.metadata import TargetFile


TESTS = Path(__file__).resolve().parent
TOOLS = TESTS.parent / "tools"
DEPOT_IP = "10.0.2.100"
CHANNEL = "stable"
CHECKED = b"FVCA_PERMIT_LAB_RESTART_CHECKED"


def write(path, body):
    path.write_text(json.dumps(body) + "\n", encoding="utf-8")
    return sha256(path.read_bytes()).hexdigest()


def request(issued):
    return json.loads((issued / "permit.json").read_bytes())["acknowledgment"]


def prepare(args):
    scope = request(args.issued)
    stem = {"guest": scope["guest"], "service": scope["service"], "channel": CHANNEL}
    if any(re.fullmatch(r"[a-z][a-z0-9-]{0,63}", stem[name]) is None for name in ("guest", "service")):
        raise ValueError("expected canonical Guest and service names in the permit")
    permit = sha256((args.issued / "permit.json").read_bytes()).hexdigest()
    channel = f"{stem['guest']}.{stem['service']}.{CHANNEL}"
    notice = f"fvca-permit.{channel}.{permit}.stop.json"
    if args.notice.name != notice:
        raise ValueError("expected the exact channel stop target for the supplied permit")
    args.output.mkdir(mode=0o700)
    depot = args.output / "depot"
    (depot / "targets").mkdir(parents=True)
    now = datetime.now(UTC)
    timestamp = int(now.timestamp())
    head = json.dumps({**stem, "schema": "fvca-workload-channel-head-v1", "sequence": 1,
                       "valid_from": timestamp - 60, "expires": max(timestamp, scope["expires"]) + 3600,
                       "release": None}).encode("utf-8")
    targets = {}
    for name, content in ((f"fvca-workload.{channel}.json", head), (notice, args.notice.read_bytes())):
        target = TargetFile.from_data(name, content, ["sha256"])
        targets[name] = target
        (depot / "targets" / f"{target.hashes['sha256']}.{name}").write_bytes(content)
    tuf = runpy.run_path(str(TESTS / "check-release-intake.py"))
    tuf["publish"](depot, (1, 1), tuf["new_keys"](), now, targets)
    https = runpy.run_path(str(TESTS / "check-release-https.py"))
    _, _, authority = https["certificate"](args.output, "permit-lab-ca")
    https["certificate"](args.output, DEPOT_IP, authority)
    (args.output / "permit-lab-ca.key").unlink()
    depot_hash = write(args.output / "depot.json", {
        "transport": "https", "base_url": f"https://{DEPOT_IP}/fvca/depot/",
        "ca_file": "/run/fvca/workload-trust/channel-ca.pem", "deadline_seconds": 30,
    })
    write(args.output / "channel.json", {**stem, "schema": "fvca-workload-channel-policy-v1",
          "tuf_root_sha256": sha256((depot / "metadata/1.root.json").read_bytes()).hexdigest(),
          "depot_config_sha256": depot_hash, "max_artifact_bytes": 16 * 1024**2})
    (args.output / "notice").write_text(notice + "\n", encoding="ascii")
    (args.output / "uplink").write_text(
        "FVCA-GUEST-WORKLOAD-NETWORK-1\npci=0000:00:06.0\nmac=52:54:00:7d:ce:01\n"
        f"address=10.0.2.15/24\ngateway=none\nmtu=1500\ndns=none\negress=tcp,{DEPOT_IP},443\n",
        encoding="ascii",
    )


def rtc(timestamp):
    return datetime.fromtimestamp(timestamp, UTC).strftime("%Y-%m-%dT%H:%M:%S")


def check(args):
    sys.path.insert(0, str(TOOLS))
    from guest_boot_bundle import verify

    storage = runpy.run_path(str(TESTS / "check-storage.py"))
    https = runpy.run_path(str(TESTS / "check-release-https.py"))
    command_line, _ = verify(args.bundle, args.release_certificate)
    scope = request(args.issued)
    expires = scope["expires"]
    notice = (args.enrollment / "notice").read_bytes().strip()
    prefix = f"fvca-permit.{scope['guest']}.{scope['service']}.{CHANNEL}.".encode("ascii")
    leaf = notice.removeprefix(prefix)
    if leaf == notice:
        raise ValueError("the enrolled revocation target differs from the permit scope")
    args.output.mkdir(mode=0o700)
    client = argparse.Namespace(
        guest=True, direct_boot=args.bundle, direct_cmdline=command_line,
        disk=args.bundle / "core.raw", runtime=args.bundle / "runtime.raw", output=args.output,
    )

    def boot(name, data, timestamp, marker, timeout, *, persistent=False):
        client.persistent_members = persistent
        prompts, output = storage["boot"](client, name, None, data, ready_marker=marker, timeout=timeout,
                                          rtc_base=rtc(timestamp), workload_depot_tap=True)
        if prompts:
            raise ValueError(f"{name} unexpectedly requested storage credentials")
        return storage["rejoin_serial_output"](output)

    with tempfile.TemporaryDirectory(prefix=".permit-data-", dir=args.output) as directory:
        data = Path(directory) / "data.raw"
        subprocess.run(["cp", "--reflink=auto", "--sparse=always", "--", args.data, data], check=True)
        tls = tuple(args.enrollment / f"{DEPOT_IP}.{suffix}" for suffix in ("pem", "key"))
        with https["serve"](args.enrollment / "depot", tls, (DEPOT_IP, 443)) as server:
            live = boot("live-revocation", data, expires - 25, CHECKED, 190, persistent=True)
            requested = tuple(server.requests)
        if storage["READY"] not in live or storage["FAIL"] in live or b"FVCA_WORKLOAD_STARTED" not in live:
            raise ValueError("the enrolled unsigned workload did not complete its ordinary start")
        events = (
            rb'"condition":"current"', rb'"condition":"permit-expired"', b"FVCA_PERMIT_LAB_ACTIVE_AFTER_EXPIRY",
            b"FVCA_WORKLOAD_PERMIT_NOTICE_RETAINED " + leaf, rb'"condition":"revoked-stop"',
            b"FVCA_PERMIT_LAB_CHECK_STOPPED", b"FVCA_PERMIT_LAB_RESTART_ATTEMPT", CHECKED,
        )
        offset = 0
        for event in events:
            position = live.find(event, offset)
            if position < 0:
                raise ValueError(f"the live Guest missed {event.decode()} in sequence")
            offset = position + len(event)
        stopped = live.split(b"FVCA_PERMIT_LAB_CHECK_STOPPED", 1)[1].split(CHECKED, 1)[0]
        before, after = stopped.split(b"FVCA_PERMIT_LAB_RESTART_ATTEMPT", 1)
        inactive = rb"systemctl\[\d+\]: inactive\r?\n"
        rejection = after.find(b"UNSIGNED_UPSTREAM_APPROVED workload is outside its authorized start period")
        if not re.search(inactive, before) or rejection < 0 or not re.search(inactive, after[rejection:]):
            raise ValueError("systemd did not keep the service inactive through the restart request")
        if (not any(path.endswith(notice.decode("ascii")) for path in requested)
                or any(path.endswith("-workload.raw") for path in requested)):
            raise ValueError("HTTPS did not deliver the exact notice independently of an update image")
        print("live-expiry-and-signed-stop passed", flush=True)

        for name, disk, timestamp, reason in (
            ("expired-start", args.data, expires + 5, b"unsigned workload permit is outside its validity period"),
            ("retained-revocation-start", data, expires - 25, b"unsigned workload permit is revoked"),
        ):
            output = boot(name, disk, timestamp, storage["FAIL"], 65)
            if reason not in output or storage["READY"] in output or b"FVCA_WORKLOAD_STARTED" in output:
                raise ValueError(f"{name} did not refuse the workload before readiness")
            print(f"{name} passed", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    for action, fields in (
        ("prepare", ("issued", "notice", "output")),
        ("check", ("issued", "enrollment", "bundle", "release-certificate", "data", "output")),
    ):
        mode = commands.add_parser(action)
        for field in fields:
            mode.add_argument(f"--{field}", type=lambda value: Path(value).absolute(), required=True)
    parser.add_argument("--isolated-from", help=argparse.SUPPRESS)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.action == "prepare":
            prepare(args)
            return
        namespace = str(os.stat("/proc/self/ns/net").st_ino)
        if args.isolated_from is None:
            os.execvp("unshare", ["unshare", "--user", "--map-root-user", "--net", sys.executable, "-B", "-W", "error",
                                 str(Path(__file__).resolve()), "--isolated-from", namespace, *sys.argv[1:]])
        if args.isolated_from == namespace:
            raise ValueError("the HTTPS depot requires an isolated network namespace")
        subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
        subprocess.run(["ip", "tuntap", "add", "dev", "fvca-depot", "mode", "tap"], check=True)
        subprocess.run(["ip", "addr", "add", f"{DEPOT_IP}/24", "dev", "fvca-depot"], check=True)
        subprocess.run(["ip", "link", "set", "dev", "fvca-depot", "up"], check=True)
        check(args)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Workload permit boot qualification failed: {error}\n")


if __name__ == "__main__":
    main()
