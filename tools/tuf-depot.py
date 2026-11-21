#!/usr/bin/env python3
"""Draft FVCA TUF metadata and atomically publish independently signed depots."""

import argparse
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
import fcntl
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

from tuf.api.exceptions import RepositoryError, UnsignedMetadataError
from tuf.api.metadata import MetaFile, Metadata, Root, Snapshot, TargetFile, Targets, Timestamp

from workload_oci import open_regular, parse_json, read_bytes


METADATA_LIMIT = 1024 * 1024
MAX_ROOT_UPDATES = 1024
U64_MAX = 2**64 - 1
MAX_TRANSFER = timedelta(seconds=86_400)  # Both FVCA depot transports enforce this upper bound.
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
    chain = [document]
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
        chain.append(document)
    return chain


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


def targets_link(snapshot):
    if snapshot.signed.meta.keys() != {"targets.json"}:
        raise ValueError("FVCA snapshot must reference only top-level targets")
    return link_profile(snapshot.signed.meta["targets.json"])


def check_link(reference, role):
    document, data = role
    if reference.version != document.signed.version:
        raise ValueError("TUF metadata version differs from its signed reference")
    reference.verify_length_and_hashes(data)


def check_targets(document):
    if document.signed.delegations is not None:
        raise ValueError("FVCA requires top-level targets without delegations")
    return {target_filename(target): target for target in document.signed.targets.values()}


def target_filename(target):
    if (not TARGET_NAME.fullmatch(target.path) or not 0 < target.length < U64_MAX
            or target.hashes.keys() != {"sha256"} or not HASH.fullmatch(target.hashes["sha256"])):
        raise ValueError(f"invalid FVCA target record for {target.path}")
    return f"{target.hashes['sha256']}.{target.path}"


def phase_files(metadata, *, versioned):
    timestamp = load(metadata / "timestamp.json", "timestamp")
    tip = link_profile(timestamp[0].signed.snapshot_meta)
    snapshot = load(metadata / (f"{tip.version}.snapshot.json" if versioned else "snapshot.json"), "snapshot")
    check_link(tip, snapshot)
    index = targets_link(snapshot[0])
    targets = load(metadata / (f"{index.version}.targets.json" if versioned else "targets.json"), "targets")
    check_link(index, targets)
    check_targets(targets[0])
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


def depot_files(depot):
    if {entry.name for entry in depot.iterdir()} != {"metadata", "targets"}:
        raise ValueError("live depot must contain only metadata and targets directories")
    metadata = regular_files(depot / "metadata")
    targets = regular_files(depot / "targets")
    for name in metadata.keys() - {"timestamp.json"}:
        if not VERSIONED.fullmatch(name):
            raise ValueError(f"unexpected published metadata name {name}")
    for name in targets:
        prefix, _, target = name.partition(".")
        if not HASH.fullmatch(prefix) or not TARGET_NAME.fullmatch(target):
            raise ValueError(f"unexpected published target name {name}")
    return metadata, targets


def make_view(ready, previous_metadata, previous_targets):
    metadata, targets = ready / "metadata", ready / "targets"
    for directory in (ready, metadata, targets):
        directory.mkdir(mode=0o755)
        directory.chmod(0o755)  # The private transaction parent protects the incomplete view.
    for destination, files in ((metadata, previous_metadata), (targets, previous_targets)):
        for name, path in files.items():
            (destination / name).hardlink_to(path)
    return metadata, targets


def verify_historical(chain, snapshot, targets):
    for root in reversed(chain):
        try:
            verify_signature(root, "snapshot", snapshot)
            verify_signature(root, "targets", targets)
        except UnsignedMetadataError:
            continue
        return
    raise ValueError(f"historical snapshot {snapshot.signed.version} has no verified signing root")


def retirement(chain, roles, metadata, targets, clock_skew_seconds):
    now = datetime.now(UTC)
    grace = MAX_TRANSFER + timedelta(seconds=clock_skew_seconds)
    keep_metadata = {"timestamp.json", *(f"{root.signed.version}.root.json" for root in chain)}
    keep_metadata.update(f"{roles[role][0].signed.version}.{role}.json" for role in ("snapshot", "targets"))
    keep_targets = check_targets(roles["targets"][0])
    next_expiry = None
    for name, path in metadata.items():
        if name in keep_metadata or not name.endswith(".snapshot.json"):
            continue
        snapshot, _ = load(path, "snapshot")
        if name != f"{snapshot.signed.version}.snapshot.json":
            raise ValueError(f"historical snapshot version differs from {name}")
        link = targets_link(snapshot)
        index_name = f"{link.version}.targets.json"
        index = load(metadata[index_name], "targets")
        check_link(link, index)
        verify_historical(chain, snapshot, index[0])
        referenced = check_targets(index[0])
        # Older views can have an in-flight client at the edge of their signed validity.
        expiry = min(snapshot.signed.expires, index[0].signed.expires) + grace
        if expiry > now:
            keep_metadata.update((name, index_name))
            for filename, target in referenced.items():
                existing = keep_targets.setdefault(filename, target)
                if existing.length != target.length:
                    raise ValueError(f"live indices disagree about the length of {filename}")
            next_expiry = expiry if next_expiry is None else min(next_expiry, expiry)

    if not keep_metadata <= metadata.keys() or not keep_targets.keys() <= targets.keys():
        raise ValueError("depot is missing an object required by a retained view")
    for name, target in keep_targets.items():
        verify_target(targets[name], target)
    return ({name: path for name, path in metadata.items() if name not in keep_metadata},
            {name: path for name, path in targets.items() if name not in keep_targets}, next_expiry)


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
        previous_metadata, previous_targets = depot_files(depot)
        previous_roots = versioned_roots(previous_metadata)
        old_root = root_chain(anchor, previous_roots)[-1]
        old_roles = phase_files(depot / "metadata", versioned=True)
        validate_roles(old_root, old_roles)

    offered_metadata = regular_files(args.signed)
    offered_roots = versioned_roots(offered_metadata)
    for version in previous_roots.keys() & offered_roots.keys():
        if previous_roots[version][1] != offered_roots[version][1]:
            raise ValueError(f"root rotation changes published version {version}")
    new_roots = previous_roots | offered_roots
    chain = root_chain(anchor, new_roots)
    root = chain[-1]
    offered_roles = phase_files(args.signed, versioned=False)
    validate_roles(root, offered_roles, datetime.now(UTC))
    if existing:
        forward(old_roles, offered_roles)

    previous_metadata.pop("timestamp.json", None)
    metadata, targets = make_view(ready, previous_metadata, previous_targets)

    anchor_version = anchor[0].signed.version
    for version, (_, data) in (new_roots | {anchor_version: anchor}).items():
        write_version(metadata / f"{version}.root.json", data)
    for role, (document, data) in offered_roles.items():
        name = "timestamp.json" if role == "timestamp" else f"{document.signed.version}.{role}.json"
        write_version(metadata / name, data)
    for target in offered_roles["targets"][0].signed.targets.values():
        install_target(target, previous_targets, args.package, targets / target_filename(target), lease_fd)
    retired = None
    if args.max_clock_skew_seconds is not None:
        metadata_files, target_files = depot_files(ready)
        drop_metadata, drop_targets, next_expiry = retirement(
            chain, offered_roles, metadata_files, target_files, args.max_clock_skew_seconds,
        )
        for file in (*drop_metadata.values(), *drop_targets.values()):
            file.unlink()
        retired = len(drop_metadata), len(drop_targets), next_expiry
    for directory in (targets, metadata, ready):
        sync_directory(directory)
    validate_roles(root, offered_roles, datetime.now(UTC))
    return offered_roles["timestamp"][0].signed.version, retired


@contextmanager
def transaction(path):
    if path.name in ("", ".", ".."):
        raise ValueError("use a dedicated child directory for the live depot")
    depot = path.parent.resolve(strict=True) / path.name
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
            yield depot, work / "depot", lease.fileno(), existing
        finally:
            shutil.rmtree(work)
            sync_directory(depot.parent)


def activate(depot, ready, lease_fd, *, existing):
    sync_directory(ready.parent)
    operation = "--exchange" if existing else "--no-clobber"
    # The child retains the writer lock if the parent dies during the exchange.
    subprocess.run(["mv", operation, "--no-copy", "-T", "--", ready, depot],
                   pass_fds=(lease_fd,), check=True)
    if not existing and ready.exists():
        raise FileExistsError(depot)
    sync_directory(depot.parent)
    sync_directory(ready.parent)


def publish(args):
    with transaction(args.depot) as (depot, ready, lease_fd, existing):
        version, retired = assemble(args, depot, ready, lease_fd, existing=existing)
        activate(depot, ready, lease_fd, existing=existing)
    print(f"FVCA_TUF_DEPOT_PUBLISHED {version}")
    if retired is not None:
        report_retired(*retired)


def report_retired(metadata, targets, next_expiry):
    deadline = int(next_expiry.timestamp()) if next_expiry is not None else "none"
    print(f"FVCA_TUF_DEPOT_RETIRED metadata={metadata} targets={targets} next_expiry={deadline}")


def prune(args):
    with transaction(args.depot) as (depot, ready, lease_fd, existing):
        if not existing:
            raise ValueError("a published depot is required for retirement")
        metadata, targets = depot_files(depot)
        chain = root_chain(load(args.trusted_root, "root"), versioned_roots(metadata))
        roles = phase_files(depot / "metadata", versioned=True)
        validate_roles(chain[-1], roles)
        drop_metadata, drop_targets, next_expiry = retirement(
            chain, roles, metadata, targets, args.max_clock_skew_seconds,
        )
        if drop_metadata or drop_targets:
            kept = make_view(ready, {name: metadata[name] for name in metadata.keys() - drop_metadata.keys()},
                             {name: targets[name] for name in targets.keys() - drop_targets.keys()})
            for directory in (*kept, ready):
                sync_directory(directory)
            activate(depot, ready, lease_fd, existing=True)
    report_retired(len(drop_metadata), len(drop_targets), next_expiry)


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


def clock_skew(value):
    seconds = int(value)
    if seconds < 0:
        raise argparse.ArgumentTypeError("clock skew must be nonnegative")
    return seconds


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
    for action, run in (("publish", publish), ("prune", prune)):
        command = commands.add_parser(action)
        command.add_argument("--depot", required=True, type=Path)
        command.add_argument("--trusted-root", required=True, type=Path, help="out-of-band bootstrap TUF root")
        command.add_argument("--max-clock-skew-seconds", type=clock_skew, required=action == "prune",
                             help="maximum clock difference between the origin and authorized clients")
        if action == "publish":
            command.add_argument("--signed", required=True, type=Path, help="signed roles and versioned root rotations")
            command.add_argument("--package", action="append", default=[], type=Path)
        command.set_defaults(run=run)
    args = parser.parse_args()
    try:
        args.run(args)
    except (RepositoryError, ValueError, TypeError, KeyError, AttributeError, OSError,
            OverflowError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"FVCA TUF depot failed: {error}\n")


if __name__ == "__main__":
    main()
