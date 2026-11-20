#!/usr/bin/env python3
"""Verify and retain independently enrolled FVCA recovery points off the appliance."""

import argparse
from contextlib import closing
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import sqlite3
import stat
import subprocess
import tempfile
import time

import backup_destination
from image_verity import verify_cms


HASH = r"[0-9a-f]{64}"
UUID = r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"
IO_DEADLINE = 120


def read(path, limit):
    with path.open("rb") as stream:
        value = stream.read(limit + 1)
    if not 0 < len(value) <= limit:
        raise ValueError(f"unexpected size for {path.name}")
    return value


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unique_properties(pairs):
    properties = dict(pairs)
    if len(properties) != len(pairs):
        raise ValueError("duplicate JSON field")
    return properties


def policy_from(args, work):
    payload = work / "authorized-policy.json"
    payload.write_bytes(read(args.policy, 65_536))
    verify_cms(payload, args.signature, args.authority)
    policy = json.loads(payload.read_bytes(), object_pairs_hook=unique_properties)
    bounds = {
        "schema": (1, 1),
        "keep_min": (1, 4096),
        "max_expire": (1, 64),
        "expire_after_seconds": (1, 3650 * 86400),
        "max_backup_age_seconds": (1, 365 * 86400),
        "bandwidth_kib": (1, 1048576),
        "operation_timeout_seconds": (60, 604800),
    }
    hashes = {"destination_sha256", "ca_sha256", "restic_sha256"}
    if type(policy) is not dict or set(policy) != set(bounds) | hashes | {"protect"}:
        raise ValueError("unexpected signed maintenance policy fields")
    for key, (minimum, maximum) in bounds.items():
        value = policy[key]
        if type(value) is not int or not minimum <= value <= maximum:
            raise ValueError(f"invalid maintenance policy field {key}")
    for key in hashes:
        if not isinstance(policy[key], str) or re.fullmatch(HASH, policy[key]) is None:
            raise ValueError(f"invalid maintenance policy field {key}")
    protected = policy["protect"]
    if not isinstance(protected, list) or any(
        not isinstance(item, str) or re.fullmatch(HASH, item) is None for item in protected
    ) or len(set(protected)) != len(protected):
        raise ValueError("invalid protected recovery-point IDs")
    return policy


def private_directory(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError(f"{path} must be a private directory owned by the maintenance account")
    return path.resolve(strict=True)


def private_file(path, modes, limit=None):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) not in modes or (limit is not None and not 0 < info.st_size <= limit)):
        raise ValueError(f"{path.name} must be a private regular file owned by the maintenance account")
    return path


class Repository:
    def __init__(self, args, policy, work):
        source = read(args.destination, 2048)
        ca = read(args.ca, 65_536)
        self.destination = backup_destination.parse(source, ca)
        self.engine = args.restic.resolve(strict=True)
        with self.engine.open("rb") as stream:
            engine_hash = hashlib.file_digest(stream, "sha256").hexdigest()
        if (digest(source), digest(ca), engine_hash) != (
            policy["destination_sha256"], policy["ca_sha256"], policy["restic_sha256"]
        ):
            raise ValueError("destination, CA or restic executable differs from signed approval")
        credentials = private_directory(args.credentials)
        password = private_file(credentials / "repository-password", {0o400, 0o600}, 4096)
        s3 = private_file(credentials / "s3-credentials", {0o400, 0o600}, 8192)
        fields = read(s3, 8192).decode("ascii").splitlines()
        if not re.fullmatch(
            r"\[default\]\naws_access_key_id *= *[A-Za-z0-9+=/_.-]+\n"
            r"aws_secret_access_key *= *[A-Za-z0-9+=/_.-]+(?:\naws_session_token *= *[A-Za-z0-9+=/_.-]+)?",
            "\n".join(fields),
        ):
            raise ValueError("invalid maintenance AWS shared credentials profile")
        ca_file = work / "s3-ca.pem"
        ca_file.write_bytes(ca)
        self.base = work
        self.timeout = policy["operation_timeout_seconds"]
        self.env = {
            "HOME": str(work), "TMPDIR": str(work), "AWS_SHARED_CREDENTIALS_FILE": str(s3),
            "AWS_PROFILE": "default", "AWS_EC2_METADATA_DISABLED": "true", "GOMAXPROCS": "2",
            "GOMEMLIMIT": "512MiB",
        }
        bandwidth = str(policy["bandwidth_kib"])
        self.command = [
            str(self.engine), "--repo", self.destination.url, "--cacert", str(ca_file), "--password-file",
            str(password), "--no-cache", "--limit-download", bandwidth, "--limit-upload", bandwidth,
            "-o", "s3.bucket-lookup=path", "-o", f"s3.region={self.destination.region}", "-o", "s3.connections=2",
        ]

    def run(self, *args, limit=0, timeout=None):
        deadline = time.monotonic() + (timeout if timeout is not None else self.timeout)
        output = bytearray()
        with subprocess.Popen(
            [*self.command, *args], cwd=self.base, env=self.env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if limit else subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        ) as child:
            try:
                if child.stdout is not None:
                    with selectors.DefaultSelector() as selector:
                        selector.register(child.stdout, selectors.EVENT_READ)
                        while True:
                            if not selector.select(max(0, deadline - time.monotonic())):
                                raise ValueError(f"restic {args[0]} timed out")
                            block = os.read(child.stdout.fileno(), 65536)
                            if not block:
                                break
                            if len(output) + len(block) > limit:
                                raise ValueError(f"restic {args[0]} reply exceeded its size bound")
                            output.extend(block)
                if child.wait(timeout=max(0, deadline - time.monotonic())):
                    raise ValueError(f"restic {args[0]} failed with status {child.returncode}")
            finally:
                if child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        child.kill()
        return bytes(output)

    def verify(self):
        config = json.loads(self.run("cat", "config", limit=65_536, timeout=IO_DEADLINE))
        if not isinstance(config, dict) or config.get("version") != 2 or config.get("id") != self.destination.repository:
            raise ValueError("repository format or ID differs from signed approval")

    def snapshots(self):
        output = self.run("list", "snapshots", limit=4 * 1024 * 1024, timeout=IO_DEADLINE).decode("ascii")
        ids = output.splitlines()
        if any(re.fullmatch(HASH, item) is None for item in ids) or len(ids) != len(set(ids)):
            raise ValueError("unexpected restic snapshot inventory")
        return set(ids)


@dataclass(frozen=True)
class Receipt:
    snapshot: str
    capture: str
    captured: int
    manifest: bytes
    receipt: bytes

    @classmethod
    def read(cls, args, repository):
        receipt = read(args.receipt, 8192)
        manifest = read(args.manifest, 8192)
        match = re.fullmatch(
            rf"FVCA-S3-BACKUP-1\ncapture=({UUID})\ndisk_sha256=({HASH})\n"
            rf"FVCA-S3-VERIFIED-1\nrepository={repository}\nsnapshot=({HASH})\n",
            receipt.decode("ascii"),
        )
        if match is None:
            raise ValueError("invalid backup receipt or repository scope")
        capture, disk, snapshot = match.groups()
        lines = manifest.decode("utf-8").splitlines()
        recorded = [line.removeprefix("capture_unix_seconds=") for line in lines if line.startswith("capture_unix_seconds=")]
        if (not manifest.startswith(b"CAPTURE_COMPLETE\n") or not manifest.endswith(b"\n")
                or [line for line in lines if line.startswith("capture_id=")] != [f"capture_id={capture}"]
                or [line for line in lines if line.startswith("disk_sha256=")] != [f"disk_sha256={disk}"]
                or len(recorded) != 1 or re.fullmatch(r"[1-9][0-9]{0,11}", recorded[0]) is None):
            raise ValueError("receipt disagrees with the finalized capture manifest")
        captured = int(recorded[0])
        if captured > int(time.time()):
            raise ValueError("capture timestamp is in the future")
        return cls(snapshot, capture, captured, manifest, receipt)

    def save(self, db, repo):
        stored = repo.run("dump", self.snapshot, "/manifest", limit=8192, timeout=IO_DEADLINE)
        if stored != self.manifest or self.snapshot not in repo.snapshots():
            raise ValueError("repository does not contain the independently supplied recovery point")
        values = (self.snapshot, self.capture, self.captured, self.manifest, self.receipt)
        with db:
            db.execute("INSERT INTO points VALUES (?, ?, ?, ?, ?, 'active') ON CONFLICT(snapshot) DO NOTHING", values)
            previous = db.execute(
                "SELECT snapshot, capture, captured, manifest, receipt, status FROM points WHERE snapshot = ?",
                (self.snapshot,),
            ).fetchone()
            if previous != (*values, "active"):
                raise ValueError("recovery point differs from independent history")
        print(f"FVCA_S3_RECEIPT_ENROLLED {self.snapshot} capture={self.capture} captured={self.captured}")


def open_ledger(directory, repository):
    database = directory / "receipts.sqlite3"
    if database.exists():
        private_file(database, {0o600})
    db = sqlite3.connect(database)
    db.execute("PRAGMA synchronous = FULL")
    with db:
        db.execute("CREATE TABLE IF NOT EXISTS repository (id TEXT PRIMARY KEY)")
        db.execute(
            "CREATE TABLE IF NOT EXISTS points (snapshot TEXT PRIMARY KEY, capture TEXT UNIQUE NOT NULL, "
            "captured INTEGER NOT NULL, manifest BLOB NOT NULL, receipt BLOB NOT NULL, "
            "status TEXT NOT NULL CHECK (status IN ('active', 'retiring', 'expired')))"
        )
        db.execute("INSERT OR IGNORE INTO repository VALUES (?)", (repository,))
        if db.execute("SELECT id FROM repository").fetchall() != [(repository,)]:
            raise ValueError("receipt ledger belongs to a different repository")
    return db


def inventory(db, repo):
    present = repo.snapshots()
    history = db.execute("SELECT snapshot, status, captured FROM points ORDER BY captured DESC, snapshot").fetchall()
    active = {snapshot: captured for snapshot, status, captured in history if status == "active"}
    pending = {snapshot: captured for snapshot, status, captured in history if status == "retiring"}
    expired = {snapshot for snapshot, status, _ in history if status == "expired"}
    for ids, warning in ((active.keys() - present, "MISSING"), (expired & present, "REAPPEARED")):
        if ids:
            print(f"FVCA_S3_{warning} {' '.join(sorted(ids))}", flush=True)
            raise ValueError("repository differs from independent receipt history")
    unknown = present - active.keys() - pending.keys()
    print(f"FVCA_S3_INVENTORY active={len(active)} retiring={len(pending)} untracked={len(unknown)}", flush=True)
    return present, active, pending, unknown


def freshness(active, now, policy):
    age = now - max(active.values()) if active else None
    print(f"FVCA_S3_RECOVERY_POINT_AGE seconds={age if age is not None else 'unknown'}", flush=True)
    if age is None or not 0 <= age <= policy["max_backup_age_seconds"]:
        raise ValueError("no independently enrolled recovery point meets the approved maximum age")


def verify_packs(db, repo, policy):
    repo.run("check", "--read-data")
    print(f"FVCA_S3_INTEGRITY repository={repo.destination.repository} coverage=all-packs verified_at={int(time.time())}",
          flush=True)
    # Log successful pack coverage even if receipt freshness or inventory needs attention.
    _, active, pending, unknown = inventory(db, repo)
    freshness(active, int(time.time()), policy)
    if pending or unknown:
        raise ValueError("repository has interrupted maintenance or snapshots without independent receipts")


def maintain(db, repo, policy, apply):
    present, active, pending, _ = inventory(db, repo)
    now = int(time.time())
    freshness(active, now, policy)
    protected = set(policy["protect"])
    if protected - active.keys():
        raise ValueError("protected IDs must be independently enrolled and outside any pending deletion")
    if len(active) < policy["keep_min"] or any(captured > now for captured in active.values()):
        raise ValueError("independent history cannot satisfy the approved retention floor")
    available = active | {snapshot: captured for snapshot, captured in pending.items() if snapshot in present}
    newest = sorted(available, key=lambda snapshot: (-available[snapshot], snapshot))
    floor = set(newest[:policy["keep_min"]])
    if pending:
        if len(pending) > policy["max_expire"] or any(
            snapshot in present and (snapshot in floor or now - captured < policy["expire_after_seconds"])
            for snapshot, captured in pending.items()
        ):
            raise ValueError("pending retirement no longer meets the signed age, batch or recovery-point floor")
        selected = sorted(pending)
    else:
        selected = [
            snapshot for snapshot in reversed(active)
            if snapshot not in (floor | protected) and now - active[snapshot] >= policy["expire_after_seconds"]
        ][:policy["max_expire"]]
    print(f"FVCA_S3_RETENTION_PLAN snapshots={len(selected)} {' '.join(selected)}".rstrip(), flush=True)
    if not apply or not selected:
        return
    repo.run("check", "--read-data")
    present, checked, checked_pending, _ = inventory(db, repo)
    if checked != active or checked_pending != pending:
        raise ValueError("independent repository state changed during maintenance validation")
    with db:
        db.executemany("UPDATE points SET status = 'retiring' WHERE snapshot = ?", ((item,) for item in selected))
    to_forget = sorted(present.intersection(selected))
    if to_forget:
        repo.run("forget", "--prune", "--", *to_forget)
    else:
        # An interrupted run may already have deleted the snapshot references.
        repo.run("prune")
    repo.run("check")
    present, _, _, _ = inventory(db, repo)
    if present.intersection(selected):
        raise ValueError("restic left retirement targets in the repository")
    with db:
        db.executemany("UPDATE points SET status = 'expired' WHERE snapshot = ?", ((item,) for item in selected))
    for snapshot in selected:
        print(f"FVCA_S3_RETIRED {snapshot}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("policy", "signature", "authority", "destination", "ca", "state", "credentials", "restic"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    commands = parser.add_subparsers(dest="operation", required=True)
    enroll = commands.add_parser("enroll", help="independently retain a verified backup receipt and manifest")
    enroll.add_argument("--receipt", type=Path, required=True)
    enroll.add_argument("--manifest", type=Path, required=True)
    commands.add_parser("verify", help="verify all packs and independently enrolled recovery-point freshness")
    retention = commands.add_parser("retain", help="plan or apply approved snapshot retention")
    retention.add_argument("--apply", action="store_true", help="forget approved snapshots and prune unreferenced packs")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix="fvca-s3-maintenance-") as temporary:
            work = Path(temporary)
            policy = policy_from(args, work)
            repo = Repository(args, policy, work)
            state = private_directory(args.state)
            lock = os.open(state / "maintenance.lock", os.O_NOFOLLOW | os.O_CREAT | os.O_RDWR, 0o600)
            with os.fdopen(lock, "rb") as handle:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                repo.verify()
                with closing(open_ledger(state, repo.destination.repository)) as db:
                    if args.operation == "enroll":
                        Receipt.read(args, repo.destination.repository).save(db, repo)
                    elif args.operation == "verify":
                        verify_packs(db, repo, policy)
                    else:
                        maintain(db, repo, policy, args.apply)
    except (OSError, ValueError, subprocess.SubprocessError, sqlite3.Error) as error:
        parser.exit(1, f"FVCA S3 maintenance failed: {error}\n")


if __name__ == "__main__":
    main()
