#!/usr/bin/env python3
"""Draft FVCA TUF metadata and atomically publish independently signed depots."""

import argparse
from datetime import UTC, datetime, timedelta
import fcntl
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

from tuf.api.exceptions import RepositoryError
from tuf.api.metadata import MetaFile, Metadata, Root, Snapshot, TargetFile, Targets, Timestamp

from workload_oci import open_regular, parse_json, read_bytes


METADATA_LIMIT = 1024 * 1024
MAX_ROOT_UPDATES = 1024
U64_MAX = 2**64 - 1
ROLES = {"root": Root, "targets": Targets, "snapshot": Snapshot, "timestamp": Timestamp}
ONLINE = {"snapshot": timedelta(days=7), "timestamp": timedelta(days=1)}
VERSIONED = re.compile(r"([1-9][0-9]{0,19})\.(root|snapshot|targets)\.json")
TARGET_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,189}")
HASH = re.compile(r"[a-f0-9]{64}")


def load(path, role):
    data = read_bytes(path, METADATA_LIMIT)
    document = Metadata.from_dict(parse_json(data))
    if (type(document.signed) is not ROLES[role] or type(document.signed.version) is not int
            or not 0 < document.signed.version <= U64_MAX):
        raise ValueError(f"invalid {role} metadata in {path.name}")
    return document, data


def verify_signature(root, role, document):
    root.signed.verify_delegate(role, document.signed_bytes, document.signatures)


def verify_root(document):
    root = document.signed
    if (root.consistent_snapshot is not True or root.roles.keys() != ROLES.keys()
            or root.version > U64_MAX - MAX_ROOT_UPDATES):
        raise ValueError("TUF root must use FVCA's top-level consistent snapshot profile")
    public_keys = set()
    for role in root.roles.values():
        if not 1 <= role.threshold <= len(role.keyids):
            raise ValueError("unreachable TUF role threshold")
        for identity in role.keyids:
            key = root.keys[identity]
            public = key.keyval.get("public")
            if (key.keytype != "ed25519" or key.scheme != "ed25519" or not isinstance(public, str)
                    or not HASH.fullmatch(public) or public in public_keys):
                raise ValueError("TUF roles require distinct Ed25519 keys")
            public_keys.add(public)
    verify_signature(document, "root", document)


def root_chain(anchor, roots):
    document, pinned = anchor
    start = document.signed.version
    verify_root(document)
    if start in roots and roots[start][1] != pinned:
        raise ValueError("published root differs from the out-of-band trust anchor")
    versions = sorted(version for version in roots if version != start)
    if len(versions) >= MAX_ROOT_UPDATES:
        raise ValueError("root history exceeds the updater's rotation bound")
    for wanted, version in enumerate(versions, start=start + 1):
        next_root, _ = roots[version]
        if version != wanted or next_root.signed.version != version:
            raise ValueError("root rotations must form a contiguous versioned chain")
        verify_signature(document, "root", next_root)
        verify_root(next_root)
        document = next_root
    return document


def fresh(document, now):
    role = document.signed.type
    remaining = document.signed.expires - now
    if remaining <= timedelta(0) or (role in ONLINE and remaining > ONLINE[role]):
        raise ValueError(f"{role} metadata expiry is outside FVCA's validity window")


def link_profile(reference):
    if (reference.length is None or not 0 < reference.length <= METADATA_LIMIT or not reference.hashes
            or reference.hashes.keys() != {"sha256"} or not HASH.fullmatch(reference.hashes["sha256"])
            or not 0 < reference.version <= U64_MAX):
        raise ValueError("TUF links require an exact version, length and SHA-256")
    return reference


def target_filename(target):
    if (not TARGET_NAME.fullmatch(target.path) or not 0 < target.length < U64_MAX
            or target.hashes.keys() != {"sha256"} or not HASH.fullmatch(target.hashes["sha256"])):
        raise ValueError(f"invalid FVCA target record for {target.path}")
    return f"{target.hashes['sha256']}.{target.path}"


def phase_files(metadata, *, versioned):
    timestamp = load(metadata / "timestamp.json", "timestamp")
    tip = link_profile(timestamp[0].signed.snapshot_meta)
    snapshot = load(metadata / (f"{tip.version}.snapshot.json" if versioned else "snapshot.json"), "snapshot")
    if snapshot[0].signed.meta.keys() != {"targets.json"}:
        raise ValueError("FVCA snapshot must reference only top-level targets")
    index = link_profile(snapshot[0].signed.meta["targets.json"])
    targets = load(metadata / (f"{index.version}.targets.json" if versioned else "targets.json"), "targets")
    for reference, (document, data) in ((tip, snapshot), (index, targets)):
        if reference.version != document.signed.version:
            raise ValueError("TUF metadata version differs from its signed reference")
        reference.verify_length_and_hashes(data)
    if targets[0].signed.delegations is not None:
        raise ValueError("FVCA requires top-level targets without delegations")
    for target in targets[0].signed.targets.values():
        target_filename(target)
    return {"timestamp": timestamp, "snapshot": snapshot, "targets": targets}


def validate_roles(root, roles, now=None):
    if now is not None:
        fresh(root, now)
    for role, (document, _) in roles.items():
        verify_signature(root, role, document)
        if now is not None:
            fresh(document, now)


def forward(previous, offered):
    for role, (document, data) in offered.items():
        old, old_bytes = previous[role]
        if document.signed.version < old.signed.version:
            raise ValueError(f"{role} metadata would roll the published depot back")
        if document.signed.version == old.signed.version and data != old_bytes:
            raise ValueError(f"{role} metadata changes an already published version")


def regular_files(directory):
    if not stat.S_ISDIR(directory.stat(follow_symlinks=False).st_mode):
        raise ValueError(f"expected a real directory: {directory}")
    files = {}
    for entry in directory.iterdir():
        if not stat.S_ISREG(entry.stat(follow_symlinks=False).st_mode):
            raise ValueError(f"expected a regular depot entry: {entry.name}")
        files[entry.name] = entry
    return files


def versioned_roots(files):
    return {int(match[1]): load(path, "root") for name, path in files.items()
            if (match := VERSIONED.fullmatch(name)) and match[2] == "root"}


def verify_target(path, target):
    with open_regular(path) as stream:
        target.verify_length_and_hashes(stream)


def install_target(target, old_files, sources, ready, lease_fd):
    name = target_filename(target)
    previous = old_files.get(name)
    if previous is not None:
        verify_target(previous, target)
        return  # The previous inode is already linked into the staged depot.
    incoming = next((path / "targets" / name for path in sources if (path / "targets" / name).exists()), None)
    if incoming is None:
        raise ValueError(f"signed target has no payload: {target.path}")
    with open_regular(incoming) as stream:
        if os.fstat(stream.fileno()).st_size != target.length:
            raise ValueError(f"payload length differs from signed target: {target.path}")
        subprocess.run([
            "cp", "--reflink=auto", "--sparse=always", "--", f"/proc/self/fd/{stream.fileno()}", ready,
        ], pass_fds=(stream.fileno(), lease_fd), check=True)
    with open_regular(ready) as stream:
        target.verify_length_and_hashes(stream)
        os.fchmod(stream.fileno(), 0o444)
        os.fsync(stream.fileno())


def sync_directory(path):
    fd = os.open(path, os.O_DIRECTORY | os.O_NOFOLLOW | os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_version(path, data):
    if path.exists():
        if read_bytes(path, METADATA_LIMIT) != data:
            raise ValueError(f"immutable depot metadata already exists: {path.name}")
        return
    with path.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fchmod(stream.fileno(), 0o444)
        os.fsync(stream.fileno())


def assemble(args, depot, ready, lease_fd, *, existing):
    anchor = load(args.trusted_root, "root")
    previous_metadata, previous_targets = {}, {}
    previous_roots = {}
    if existing:
        if {entry.name for entry in depot.iterdir()} != {"metadata", "targets"}:
            raise ValueError("live depot must contain only metadata and targets directories")
        previous_metadata = regular_files(depot / "metadata")
        previous_targets = regular_files(depot / "targets")
        previous_roots = versioned_roots(previous_metadata)
        old_root = root_chain(anchor, previous_roots)
        old_roles = phase_files(depot / "metadata", versioned=True)
        validate_roles(old_root, old_roles)

    offered_metadata = regular_files(args.signed)
    offered_roots = versioned_roots(offered_metadata)
    for version in previous_roots.keys() & offered_roots.keys():
        if previous_roots[version][1] != offered_roots[version][1]:
            raise ValueError(f"root rotation changes published version {version}")
    new_roots = previous_roots | offered_roots
    root = root_chain(anchor, new_roots)
    offered_roles = phase_files(args.signed, versioned=False)
    validate_roles(root, offered_roles, datetime.now(UTC))
    if existing:
        forward(old_roles, offered_roles)

    metadata, targets = ready / "metadata", ready / "targets"
    for directory in (ready, metadata, targets):
        directory.mkdir(mode=0o755)
        directory.chmod(0o755)  # The private transaction parent keeps the incomplete view inaccessible.
    for name, path in previous_metadata.items():
        if name != "timestamp.json":
            if not VERSIONED.fullmatch(name):
                raise ValueError(f"unexpected published metadata name {name}")
            (metadata / name).hardlink_to(path)
    for name, path in previous_targets.items():
        prefix, _, target = name.partition(".")
        if not HASH.fullmatch(prefix) or not TARGET_NAME.fullmatch(target):
            raise ValueError(f"unexpected published target name {name}")
        (targets / name).hardlink_to(path)

    anchor_version = anchor[0].signed.version
    for version, (_, data) in (new_roots | {anchor_version: anchor}).items():
        write_version(metadata / f"{version}.root.json", data)
    for role, (document, data) in offered_roles.items():
        name = "timestamp.json" if role == "timestamp" else f"{document.signed.version}.{role}.json"
        write_version(metadata / name, data)
    for target in offered_roles["targets"][0].signed.targets.values():
        install_target(target, previous_targets, args.package, targets / target_filename(target), lease_fd)
    for directory in (targets, metadata, ready):
        sync_directory(directory)
    validate_roles(root, offered_roles, datetime.now(UTC))
    return offered_roles["timestamp"][0].signed.version


def publish(args):
    if args.depot.name in ("", ".", ".."):
        raise ValueError("use a dedicated child directory for the live depot")
    depot = args.depot.parent.resolve(strict=True) / args.depot.name
    work = depot.with_name(f".{depot.name}.publish")
    lock = depot.with_name(f".{depot.name}.publish.lock")
    flags = os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_RDONLY
    with os.fdopen(os.open(lock, flags, 0o600), "rb") as lease:
        info = os.fstat(lease.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError("invalid depot publication lock")
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if work.exists() or work.is_symlink():
            info = work.stat(follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise ValueError("invalid abandoned publication directory")
            if not {entry.name for entry in work.iterdir()} <= {"depot"}:
                raise ValueError("unexpected entries in the abandoned publication directory")
            shutil.rmtree(work)
        work.mkdir(mode=0o700)
        try:
            existing = depot.exists() or depot.is_symlink()
            if existing and not stat.S_ISDIR(depot.stat(follow_symlinks=False).st_mode):
                raise ValueError("the live depot must be a real directory")
            ready = work / "depot"
            version = assemble(args, depot, ready, lease.fileno(), existing=existing)
            sync_directory(work)
            operation = "--exchange" if existing else "--no-clobber"
            # The child retains the writer lock if the parent dies while exchanging directories.
            subprocess.run(["mv", operation, "--no-copy", "-T", "--", ready, depot],
                           pass_fds=(lease.fileno(),), check=True)
            if not existing and ready.exists():
                raise FileExistsError(depot)
            sync_directory(depot.parent)
            sync_directory(work)
        finally:
            shutil.rmtree(work)
            sync_directory(depot.parent)
    print(f"FVCA_TUF_DEPOT_PUBLISHED {version}")


def draft(args):
    role = args.command.removeprefix("draft-")
    expires = datetime.fromtimestamp(args.expires, UTC)
    if not 0 < args.version <= U64_MAX:
        raise ValueError("use a positive TUF metadata version")
    if role == "targets":
        targets = {}
        for package in args.package:
            records = parse_json(read_bytes(package / "target-records.json", METADATA_LIMIT))
            for name, record in records.items():
                target = TargetFile.from_dict(record, name)
                verify_target(package / "targets" / target_filename(target), target)
                if name in targets and targets[name] != target:
                    raise ValueError(f"conflicting package records for {name}")
                targets[name] = target
        document = Metadata(Targets(version=args.version, expires=expires, targets=targets))
    else:
        prior = "targets" if role == "snapshot" else "snapshot"
        previous, data = load(args.input, prior)
        root, _ = load(args.trusted_root, "root")
        verify_root(root)
        validate_roles(root, {prior: (previous, data)}, datetime.now(UTC))
        reference = MetaFile.from_data(previous.signed.version, data, ["sha256"])
        document = Metadata(Snapshot(version=args.version, expires=expires, meta={"targets.json": reference})
                            if role == "snapshot" else
                            Timestamp(version=args.version, expires=expires, snapshot_meta=reference))
    fresh(document, datetime.now(UTC))
    data = document.to_bytes()
    if len(data) > METADATA_LIMIT:
        raise ValueError("draft exceeds the FVCA metadata limit")
    sys.stdout.buffer.write(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("targets", "snapshot", "timestamp"):
        command = commands.add_parser(f"draft-{name}")
        command.add_argument("--version", required=True, type=int)
        command.add_argument("--expires", required=True, type=int, help="Unix seconds")
        if name == "targets":
            command.add_argument("--package", action="append", default=[], type=Path)
        else:
            command.add_argument("--trusted-root", required=True, type=Path, help="trusted current TUF root")
            command.add_argument("--input", required=True, type=Path, help="signed preceding role metadata")
        command.set_defaults(run=draft)
    command = commands.add_parser("publish")
    command.add_argument("--depot", required=True, type=Path)
    command.add_argument("--trusted-root", required=True, type=Path, help="out-of-band bootstrap TUF root")
    command.add_argument("--signed", required=True, type=Path, help="signed roles and versioned root rotations")
    command.add_argument("--package", action="append", default=[], type=Path)
    command.set_defaults(run=publish)
    args = parser.parse_args()
    try:
        args.run(args)
    except (RepositoryError, ValueError, TypeError, KeyError, AttributeError, OSError,
            OverflowError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"FVCA TUF depot failed: {error}\n")


if __name__ == "__main__":
    main()
