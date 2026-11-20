#!/usr/bin/env python3
"""Qualify matched FVCA release tuples and atomic inactive-slot preparation on Btrfs."""

import argparse
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import runpy
import selectors
import subprocess
import time

from tuf.api.metadata import TargetFile


def fixture(args):
    publish_tools = runpy.run_path(Path(__file__).with_name("check-release-intake.py"))
    publish = publish_tools["publish"]
    new_keys = publish_tools["new_keys"]
    make_release = publish_tools["make_release"]
    require = publish_tools["require"]
    write_json = publish_tools["write_json"]
    sha256 = publish_tools["sha256"]

    args.output.mkdir(mode=0o700)
    depot = args.output / "depot"
    targets = depot / "targets"
    targets.mkdir(parents=True)
    qualification = args.output / "qualification.json"
    write_json(qualification, {"profile": "disposable Btrfs slot qualification"})
    member = {"qualification.json": qualification}

    active_vm = {**member, "boot.raw": args.active_boot, "vm-runtime.raw": args.vm_runtime,
                 "guest-boot.raw": args.active_guest}
    updated_vm = {**member, "boot.raw": args.next_boot, "vm-runtime.raw": args.vm_runtime,
                  "guest-boot.raw": args.next_guest}
    releases = {
        "host-a": (active_vm, 17, "hypervisor"),
        "host-b": (updated_vm, 18, "hypervisor"),
        "host-new": (updated_vm, 19, "hypervisor"),
        "guest-a": ({**member, "guest-boot.raw": args.active_guest}, 23, "service-guest"),
        "guest-b": ({**member, "guest-boot.raw": args.next_guest}, 24, "service-guest"),
    }
    index = {}
    selections = {}
    for name, (payloads, epoch, role) in releases.items():
        selection, files = make_release(args.output, payloads, epoch, role)
        # Preserve the eligible active release for recovery throughout preparation.
        selection["minimum_epoch"] = 17 if role == "hypervisor" else 23
        selections[name] = selection
        for logical, path in files.items():
            reference = TargetFile.from_file(logical, str(path), ["sha256"])
            index[logical] = reference
            os.link(path, targets / f"{reference.hashes['sha256']}.{logical}")
    now = datetime.now(UTC).replace(microsecond=0)
    publish(depot, (1, 1), new_keys(), now, index)
    root = depot / "metadata/1.root.json"
    config = args.output / "depot.json"
    write_json(config, {"transport": "local", "path": str(depot)})
    cache = args.output / "cache"
    cache.mkdir(mode=0o700)
    host = args.output / "hypervisor-slots"
    guest = args.output / "guest-slots"
    for store in (host, guest):
        store.mkdir(mode=0o700)

    def command_for(name, selection, *options):
        selected = args.output / f"{name}-selection.json"
        write_json(selected, selection)
        return [args.client, root, config, cache, selected, *options]

    def intake(name, selection, *options, failure=None):
        command = command_for(name, selection, *options)
        result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=120)
        (args.output / f"{name}.log").write_text(result.stdout + result.stderr)
        if failure:
            require(result.returncode != 0 and failure.lower() in result.stderr.lower()
                    and "FVCA_SLOT_PREPARED " not in result.stdout, f"{name} did not reject: {result}")
        else:
            require(result.returncode == 0 and "FVCA_SLOT_PREPARED " in result.stdout, f"{name} failed: {result}")
        print(f"{name} passed", flush=True)

    def active_record(name, selection, slot="a"):
        record = args.output / f"{name}.json"
        write_json(record, {"slot": slot, "epoch": selection["epoch"],
                            "manifest_sha256": selection["manifest_sha256"]})
        return record

    def contents(path):
        return {item.name: sha256(item) for item in path.iterdir()}

    def verify_slot(store, slot, name):
        installed = store / f"slot-{slot}"
        manifest = json.loads((installed / "release.json").read_text())
        require(manifest["epoch"] == selections[name]["epoch"], "incorrect installed epoch")
        prefix = f"{selections[name]['role']}-{manifest['epoch']}-"
        expected = {logical.removeprefix(prefix): reference.hashes["sha256"]
                    for logical, reference in index.items() if logical.startswith(prefix)}
        require(contents(installed) == expected, "installed slot differs from its signed tuple")
        require(all(item.stat().st_ino != (cache / "staged" / expected["release.json"] / item.name).stat().st_ino
                    for item in installed.iterdir()), "slot member aliases the intake cache")

    intake("seed-host", selections["host-a"], "--initialize-slots", host)
    verify_slot(host, "a", "host-a")
    active_inode = (host / "slot-a").stat().st_ino
    intake("retry-seed", selections["host-a"], "--initialize-slots", host)
    require((host / "slot-a").stat().st_ino == active_inode, "initialization retry replaced slot A")
    old = contents(host / "slot-a")
    host_active = active_record("host-active", selections["host-a"])
    wrong = active_record("wrong-active", selections["host-a"] | {"manifest_sha256": "f" * 64})
    intake("wrong-active", selections["host-b"], "--prepare-inactive", host, wrong,
           failure="does not match the approved slot identity")
    require(not (host / "slot-b").exists(), "wrong boot authorization wrote to the inactive slot")
    intake("double-seed", selections["host-b"], "--initialize-slots", host, failure="empty A/B slot store")
    intake("same-epoch", selections["host-a"], "--prepare-inactive", host, host_active, failure="advance the active epoch")
    intake("wrong-role", selections["guest-b"] | {"minimum_epoch": 17}, "--prepare-inactive", host, host_active,
           failure="changes the authorized role")
    intake("raise-floor", selections["host-b"] | {"minimum_epoch": 18}, "--prepare-inactive", host, host_active,
           failure="outside the approved recovery epoch")

    (host / "slot-b").symlink_to(host / "slot-a", target_is_directory=True)
    intake("symlink-slot", selections["host-b"], "--prepare-inactive", host, host_active, failure="mode 0700")
    (host / "slot-b").unlink()
    intake("prepare-host", selections["host-b"], "--prepare-inactive", host, host_active)
    verify_slot(host, "b", "host-b")
    inode = (host / "slot-b").stat().st_ino
    intake("retry-host", selections["host-b"], "--prepare-inactive", host, host_active)
    require((host / "slot-b").stat().st_ino == inode, "retry replaced a matching inactive slot")

    # The intake rejects a damaged repository artifact before starting the installer.
    partial = targets / next(path.name for path in targets.glob("*.hypervisor-19-vm-runtime.raw"))
    partial.unlink()
    partial.write_bytes(b"incomplete repository transfer")
    intake("damaged-download", selections["host-new"], "--prepare-inactive", host, host_active, failure="hash mismatch")
    verify_slot(host, "a", "host-a")
    verify_slot(host, "b", "host-b")
    partial.unlink()
    os.link(args.vm_runtime, partial)

    # Kill the coordinator after sysupdate installs into its private root and before publication to slot B.
    command = command_for("interrupt", selections["host-new"], "--prepare-inactive", host, host_active)
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as child, \
            selectors.DefaultSelector() as events:
        events.register(child.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + 120
        log = bytearray()
        while b"Successfully installed update" not in log and events.select(max(0, deadline - time.monotonic())):
            data = os.read(child.stdout.fileno(), 65536)
            if not data:
                break
            log.extend(data)
        try:
            require(b"Successfully installed update" in log, "installer did not reach the private prepared state")
            child.kill()
            remainder, _ = child.communicate(timeout=15)
            log.extend(remainder)
            require(child.returncode < 0 and b"FVCA_SLOT_PREPARED " not in log, "interrupted update published a slot")
        finally:
            if child.poll() is None:
                child.kill()
    (args.output / "interrupt.log").write_bytes(log)
    verify_slot(host, "a", "host-a")
    verify_slot(host, "b", "host-b")
    interrupted = list(host.glob(".prepare-*"))
    require(len(interrupted) == 1, "interrupted install did not leave only one private transaction")
    print("Interruption after sysupdate preserved both published slots", flush=True)

    intake("replace-host", selections["host-new"], "--prepare-inactive", host, host_active)
    verify_slot(host, "b", "host-new")
    require((host / "slot-b").stat().st_ino != inode, "replacement reused the old inactive directory")
    require(contents(host / "slot-a") == old, "inactive preparation changed the active slot")
    print("Active Hypervisor slot preserved across failures, retries and replacement", flush=True)

    intake("seed-guest", selections["guest-a"], "--initialize-slots", guest)
    guest_active = active_record("guest-active", selections["guest-a"])
    intake("prepare-guest", selections["guest-b"], "--prepare-inactive", guest, guest_active)
    verify_slot(guest, "a", "guest-a")
    verify_slot(guest, "b", "guest-b")
    require(list(host.glob(".prepare-*")) == interrupted and not list(guest.glob(".prepare-*")),
            "normal preparation changed abandoned work or left new transaction files")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("client", "active-boot", "next-boot", "vm-runtime", "active-guest", "next-guest", "output"):
        parser.add_argument(f"--{name}", type=lambda path: Path(path).absolute(), required=True)
    args = parser.parse_args()
    os.umask(0o077)
    fixture(args)


if __name__ == "__main__":
    main()
