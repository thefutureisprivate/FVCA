"""Derive an unsigned EROFS and dm-verity tree in the workload worker."""

from contextlib import contextmanager
import gzip
import hashlib
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import tarfile
import tempfile
from uuid import UUID

import workload_oci as oci


CONVERTER_PACKAGES = (
    "umoci", "erofs-utils", "veritysetup", "zstd", "python3",
)
MAX_ENTRIES = 100_000
MOUNT_DIRECTORIES = (
    "/dev/pts", "/dev/shm", "/dev/mqueue", "/proc", "/sys/fs/cgroup", "/run", "/tmp", "/var/tmp",
)


def archive_path(name):
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or not name or "\0" in name:
        raise ValueError(f"invalid OCI archive path {name!r}")
    return path


def check_member(member):
    path = archive_path(member.name)
    if not path.parts and not member.isdir():
        raise ValueError("archive root is not a directory")
    if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE, tarfile.SYMTYPE, tarfile.LNKTYPE):
        raise ValueError(f"unsupported OCI object type at {path}")
    if member.issparse() or member.size < 0 or member.uid not in range(65536) or member.gid not in range(65536):
        raise ValueError(f"invalid OCI inode metadata at {path}")
    if path.name.startswith(".wh.") and (
        not member.isfile() or member.size != 0 or path.name in (".wh.", ".wh..", ".wh...")
    ):
        raise ValueError(f"invalid OCI whiteout at {path}")
    if member.islnk() and not archive_path(member.linkname).parts:
        raise ValueError(f"empty OCI hardlink target at {path}")
    if member.issym():
        if not member.linkname or "\0" in member.linkname:
            raise ValueError(f"invalid OCI symlink at {path}")
        target = PurePosixPath(member.linkname)
        depth = 0 if target.is_absolute() else len(path.parent.parts)
        for part in (target.parts[1:] if target.is_absolute() else target.parts):
            depth += -1 if part == ".." else 1
            if depth < 0:
                raise ValueError(f"OCI symlink escapes the image at {path}")
    for attribute in member.pax_headers:
        if attribute in ("path", "linkpath", "uid", "gid", "size", "uname", "gname", "mtime", "atime", "ctime"):
            continue
        if attribute == "SCHILY.xattr.security.capability" and member.isfile():
            continue
        raise ValueError(f"unsupported OCI extended metadata {attribute!r} at {path}")


@contextmanager
def expanded_layer(path, media_type):
    if media_type == f"{oci.LAYER}+zstd":
        with subprocess.Popen(["/usr/bin/zstd", "-dc", "--", path], stdout=subprocess.PIPE) as command:
            try:
                yield command.stdout
                if command.wait() != 0:
                    raise ValueError("zstd rejected the OCI layer")
            finally:
                command.stdout.close()
                if command.poll() is None:
                    command.kill()
                command.wait()
    elif media_type == f"{oci.LAYER}+gzip":
        with gzip.open(path, "rb") as stream:
            yield stream
    else:
        with oci.open_regular(path) as stream:
            yield stream


def qualify_layers(layout, layers, diffs, scratch):
    budget = oci.DECOMPRESSED_LIMIT
    entries = 0
    for layer, expected_diff in zip(layers, diffs, strict=True):
        path = oci.blob_path(layout, layer["digest"])
        if oci.file_record(path, layer["size"]) != {"digest": layer["digest"], "size": layer["size"]}:
            raise ValueError("staged OCI layer differs from its descriptor")
        digest = hashlib.sha256()
        with tempfile.TemporaryFile(dir=scratch) as raw, expanded_layer(path, layer["mediaType"]) as stream:
            while chunk := stream.read(1024 * 1024):
                budget -= len(chunk)
                if budget < 0:
                    raise ValueError("expanded OCI layers exceed the conversion limit")
                raw.write(chunk)
                digest.update(chunk)
            if f"sha256:{digest.hexdigest()}" != expected_diff:
                raise ValueError("expanded OCI layer differs from its signed diff ID")
            raw.seek(0)
            with tarfile.open(fileobj=raw, mode="r:") as archive:
                for member in archive:
                    entries += 1
                    if entries > MAX_ENTRIES:
                        raise ValueError("OCI layers exceed the entry limit")
                    check_member(member)


def real_directory(root, path, *, create=False):
    current = root
    for part in PurePosixPath(path).parts[1:]:
        current /= part
        if create:
            current.mkdir(mode=0o755, exist_ok=True)
        if current.is_symlink() or not current.is_dir():
            raise ValueError(f"expected a real directory at {path}")
    return current


def prepare_mounts(root):
    added = []
    for path in MOUNT_DIRECTORIES:
        if not os.path.lexists(root / path.lstrip("/")):
            real_directory(root, path, create=True)
            added.append(path)
        else:
            real_directory(root, path)
    etc = real_directory(root, "/etc")
    mtab = etc / "mtab"
    if not os.path.lexists(mtab):
        mtab.symlink_to("/proc/mounts")
        added.append("/etc/mtab")
    if not mtab.is_symlink() or os.readlink(mtab) != "/proc/mounts":
        raise ValueError("unexpected /etc/mtab in the OCI source")
    for name in ("hosts", "resolv.conf", "hostname"):
        dest = etc / name
        if not os.path.lexists(dest):
            dest.touch(mode=0o644, exist_ok=False)
            added.append(f"/etc/{name}")
        if dest.is_symlink() or not dest.is_file():
            raise ValueError(f"unexpected /etc/{name} mount destination")
    return sorted(added)


def walk_error(error):
    raise error


def strip_privilege_metadata(root):
    setid, capabilities = [], []
    for directory, dirs, names in os.walk(root, onerror=walk_error):
        for node in [Path(directory), *(Path(directory) / name for name in names)]:
            path = "/" if node == root else "/" + node.relative_to(root).as_posix()
            mode = node.lstat().st_mode
            if not (stat.S_ISDIR(mode) or stat.S_ISLNK(mode) or stat.S_ISREG(mode)) or node.name.startswith(".wh."):
                raise ValueError(f"unexpected extracted object at {path}")
            if mode & 0o6000:
                node.chmod(stat.S_IMODE(mode) & ~0o6000)
                setid.append(path)
            for attr in os.listxattr(node, follow_symlinks=False):
                if attr == "security.capability" and stat.S_ISREG(mode):
                    os.removexattr(node, attr, follow_symlinks=False)
                    capabilities.append(path)
                elif attr != "security.selinux":
                    raise ValueError(f"unexpected extracted attribute {attr!r} at {path}")
        for name in dirs:
            node = Path(directory) / name
            if node.is_symlink() and (set(os.listxattr(node, follow_symlinks=False)) - {"security.selinux"}):
                raise ValueError(f"unexpected extended metadata on symlink {node.relative_to(root)}")
    return {"set_id": sorted(setid), "file_capabilities": sorted(capabilities)}


def normalize_launch(policy, config, process, root):
    launch = oci.launch_metadata(policy, config)
    arguments = launch["entrypoint"] + launch["command"]
    executable = PurePosixPath(arguments[0])
    parent = real_directory(root, executable.parent.as_posix())
    binary = parent / executable.name
    if binary.is_symlink() or not binary.is_file() or not binary.stat().st_mode & 0o111:
        raise ValueError("OCI entrypoint must be an executable file at its approved path")
    cwd = launch["working_directory"]
    real_directory(root, cwd)
    uid, gid = (process["user"][key] for key in ("uid", "gid"))
    if (uid, gid) != (policy["uid"], policy["gid"]) or process["args"] != arguments or process["cwd"] != cwd:
        raise ValueError("resolved OCI execution identity or command differs from the approved source")
    for path in launch["volumes"]:
        real_directory(root, path)
    return launch


def stable_bytes(purpose, digest):
    return hashlib.sha256(f"fvca-workload-v1\n{purpose}\n{digest}\n".encode("ascii")).digest()


def main(staged, output, scratch):
    os.umask(0o022)
    policy_path = staged / "policy.json"
    policy_raw = oci.read_bytes(policy_path)
    policy = oci.parse_json(policy_raw)
    if policy["schema"] == "fvca-oci-explicit-exceptions-v1":
        oci.validate_exception_policy(policy)
    else:
        oci.validate_policy(policy)
    layout = staged / "oci"
    selected, config, layers, diffs, raw_launch = oci.inspect_source(
        policy, oci.read_bytes(staged / "publisher-index.json"), layout,
    )
    qualify_layers(layout, layers, diffs, scratch)
    with tempfile.TemporaryDirectory(prefix="derive-", dir=scratch) as directory:
        work = Path(directory)
        bundle = work / "bundle"
        subprocess.run(["/usr/bin/umoci", "unpack", "--image", f"{layout}:source", bundle], check=True)
        root = bundle / "rootfs"
        if root.is_symlink() or not root.is_dir():
            raise ValueError("unpacked OCI root is not a real directory")
        process = oci.parse_json(oci.read_bytes(bundle / "config.json"))["process"]
        launch = normalize_launch(policy, raw_launch, process, root)
        added = prepare_mounts(root)
        stripped = strip_privilege_metadata(root)

        contexts = work / "file-contexts"
        contexts.write_text("/.* system_u:object_r:container_file_t:s0\n", encoding="ascii")
        root_id = UUID(bytes=stable_bytes("erofs", selected["digest"])[:16], version=5)
        root_file = output / "root.erofs"
        subprocess.run([
            "/usr/bin/mkfs.erofs", "-b4096", "-T0", "-zlz4hc", "--workers=1",
            f"-U{root_id}", f"--file-contexts={contexts}", root_file, root,
        ], check=True)
    if root_file.stat().st_size % 4096:
        raise ValueError("EROFS output is not aligned to a verity block")
    salt = stable_bytes("verity-salt", selected["digest"]).hex()
    tree_id = UUID(bytes=stable_bytes("verity-uuid", selected["digest"])[:16], version=5)
    tree = output / "verity.hash"
    hash_file = output / "roothash"
    subprocess.run([
        "/usr/sbin/veritysetup", "format", "--hash=sha256", "--data-block-size=4096", "--hash-block-size=4096",
        f"--salt={salt}", f"--uuid={tree_id}", f"--root-hash-file={hash_file}", root_file, tree,
    ], check=True)
    root_hash = oci.read_bytes(hash_file, 64).decode("ascii")
    oci.digest_hex(f"sha256:{root_hash}")

    launch_bytes = oci.json_bytes(launch)
    (output / "launch.json").write_bytes(launch_bytes)
    packages = subprocess.check_output(
        ["/usr/bin/rpm", "-q", "--qf", "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\\n", *CONVERTER_PACKAGES],
        text=True,
    ).splitlines()
    evidence = {
        "schema": "fvca-workload-derivation-v1",
        "service": policy["service"],
        "source": oci.source_record(policy),
        "platform": oci.PLATFORM, "manifest": selected, "config": config,
        "layers": [{**layer, "diff_id": diff} for layer, diff in zip(layers, diffs, strict=True)],
        "source_policy": oci.sha256(policy_raw),
        "launch": oci.sha256(launch_bytes),
        "converter": {
            "packages": packages, "normalization": "fvca-workload-v1",
            "tools": {path.name: oci.sha256(oci.read_bytes(path)) for path in (Path(__file__), Path(oci.__file__))},
            "erofs": {"block_size": 4096, "timestamp": 0, "compression": "lz4hc", "uuid": str(root_id)},
            "verity": {"block_size": 4096, "algorithm": "sha256", "salt": salt, "uuid": str(tree_id)},
        },
        "transforms": {"mount_placeholders": added, "removed_privileges": stripped},
        "root": oci.file_record(root_file, oci.DECOMPRESSED_LIMIT),
        "verity_tree": oci.file_record(tree, 16 * 1024**2),
        "verity_root_hash": root_hash,
    }
    (output / "derivation.json").write_bytes(oci.json_bytes(evidence))


if __name__ == "__main__":
    try:
        main(*map(Path, sys.argv[1:]))
    except (OSError, ValueError, TypeError, KeyError, IndexError, subprocess.CalledProcessError) as error:
        sys.exit(f"FVCA workload derivation rejected: {error}")
