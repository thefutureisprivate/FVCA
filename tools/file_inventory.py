"""Inventory FVCA filesystem content and its mkosi newc initramfs."""

from compression import zstd
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

from runtime_tree import raise_walk_error


TYPES = {
    stat.S_IFDIR: "directory", stat.S_IFREG: "file", stat.S_IFLNK: "symlink",
    stat.S_IFCHR: "char-device", stat.S_IFBLK: "block-device", stat.S_IFIFO: "fifo",
    stat.S_IFSOCK: "socket",
}


def hash_bytes(stream, size):
    digest = hashlib.sha256()
    remaining = size
    while remaining:
        data = stream.read(min(remaining, 1024 * 1024))
        if not data:
            raise ValueError("truncated file content")
        digest.update(data)
        remaining -= len(data)
    return {"size": size, "sha256": digest.hexdigest()}


def device(entry, major, minor):
    if entry["type"] in ("char-device", "block-device"):
        entry.update(major=major, minor=minor)


def tree_inventory(root):
    # The trees are private copies extracted from already verified images.
    paths = [root]
    for directory, children, files in os.walk(root, onerror=raise_walk_error):
        paths.extend(Path(directory) / name for name in (*children, *files))
    paths.sort(key=lambda path: os.fsencode(path.relative_to(root)))
    entries = []
    hardlinks = {}
    for node in paths:
        info = node.lstat()
        path = "/" if node == root else "/" + node.relative_to(root).as_posix()
        entry = {"path": path, "type": TYPES[stat.S_IFMT(info.st_mode)],
                 "mode": f"{stat.S_IMODE(info.st_mode):04o}"}
        if entry["type"] == "file":
            with node.open("rb") as stream:
                entry.update(size=info.st_size, sha256=hashlib.file_digest(stream, "sha256").hexdigest())
        elif entry["type"] == "symlink":
            entry["target"] = os.readlink(node)
        device(entry, os.major(info.st_rdev), os.minor(info.st_rdev))
        if info.st_nlink > 1 and entry["type"] != "directory":
            first = hardlinks.setdefault((info.st_dev, info.st_ino), path)
            if first != path:
                entry["hardlink"] = first
        entries.append(entry)
    return entries


def read_exact(stream, length):
    data = stream.read(length)
    if len(data) != length:
        raise ValueError("truncated initramfs archive")
    return data


def skip_padding(stream, length):
    if read_exact(stream, -length % 4).strip(b"\0"):
        raise ValueError("nonzero initramfs record padding")


def archive_path(raw):
    if not raw.endswith(b"\0") or b"\0" in raw[:-1]:
        raise ValueError("invalid initramfs entry name")
    path = os.fsdecode(raw[:-1])
    if path == ".":
        return "/"
    path = path.removeprefix("./")
    if any(segment in ("", ".", "..") for segment in path.split("/")):
        raise ValueError(f"unsafe or ambiguous initramfs entry name: {path!r}")
    return "/" + path


def resolve_links(groups):
    for links in groups.values():
        if len(links) < 2:
            continue
        payloads = {(link["size"], link["sha256"]) for link in links if link["size"]}
        metadata = {(link["mode"], link["uid"], link["gid"]) for link in links}
        if len(payloads) > 1 or len(metadata) != 1:
            raise ValueError("initramfs hardlinks disagree about their content or metadata")
        source = min(links, key=lambda link: os.fsencode(link["path"]))
        if payloads:
            size, digest = payloads.pop()
        else:
            size, digest = source["size"], source["sha256"]
        for link in links:
            link.update(size=size, sha256=digest)
            if link is not source:
                link["hardlink"] = source["path"]


def newc_inventory(stream, *, capture=None):
    entries = {}
    hardlinks = {}
    while True:
        header = read_exact(stream, 110)
        if header[:6] != b"070701" or not re.fullmatch(rb"[0-9a-fA-F]{104}", header[6:]):
            raise ValueError("expected the mkosi newc initramfs format")
        ino, mode, uid, gid, nlink, _, size, dev_major, dev_minor, rmajor, rminor, namesize, checksum = (
            int(header[offset:offset + 8], 16) for offset in range(6, 110, 8)
        )
        if not 1 <= namesize <= 4096 or checksum:
            raise ValueError("invalid newc name length or checksum")
        name = read_exact(stream, namesize)
        skip_padding(stream, 110 + namesize)
        if name == b"TRAILER!!!\0":
            if size or any(chunk.strip(b"\0") for chunk in iter(lambda: stream.read(65536), b"")):
                raise ValueError("unexpected content after the mkosi initramfs archive")
            break
        path = archive_path(name)
        if path in entries:
            raise ValueError(f"duplicate initramfs entry: {path!r}")
        entry = {"path": path, "type": TYPES[stat.S_IFMT(mode)], "mode": f"{stat.S_IMODE(mode):04o}",
                 "uid": uid, "gid": gid}
        if path == "/" and entry["type"] != "directory":
            raise ValueError("initramfs root entry is not a directory")
        match entry["type"]:
            case "file":
                if capture is not None and path in capture:
                    if size > 1024 ** 2 or nlink != 1:
                        raise ValueError(f"invalid boot authorization record at {path!r}")
                    data = read_exact(stream, size)
                    capture[path] = data
                    entry.update(size=size, sha256=hashlib.sha256(data).hexdigest())
                else:
                    entry.update(hash_bytes(stream, size))
                if nlink > 1:
                    hardlinks.setdefault((dev_major, dev_minor, ino), []).append(entry)
            case "symlink":
                if not 0 < size <= 4096:
                    raise ValueError(f"invalid initramfs symbolic link at {path!r}")
                target = read_exact(stream, size)
                if b"\0" in target:
                    raise ValueError(f"invalid initramfs symbolic link at {path!r}")
                entry["target"] = os.fsdecode(target)
            case _:
                if size:
                    raise ValueError(f"unexpected initramfs payload at {path!r}")
                device(entry, rmajor, rminor)
        skip_padding(stream, size)
        entries[path] = entry
    if not entries:
        raise ValueError("empty mkosi initramfs archive")
    resolve_links(hardlinks)
    return sorted(entries.values(), key=lambda entry: os.fsencode(entry["path"]))


def initramfs_inventory(path: Path):
    with subprocess.Popen(["zstd", "-dc", "--", path], stdout=subprocess.PIPE) as process:
        with process.stdout:
            entries = newc_inventory(process.stdout)
        if process.wait():
            raise ValueError("could not decompress the authenticated initramfs")
    return entries


def composed_initramfs(path, work, capture):
    """Read ukify's Zstandard initramfs and its aligned FVCA newc suffix."""
    decoder = zstd.ZstdDecompressor()
    with path.open("rb") as source, tempfile.TemporaryFile(dir=work) as expanded:
        while not decoder.eof:
            block = source.read(1024 * 1024) if decoder.needs_input else b""
            if decoder.needs_input and not block:
                raise ValueError("truncated Zstandard frame in the composed initramfs")
            expanded.write(decoder.decompress(block, max_length=1024 * 1024))
        source.seek(-len(decoder.unused_data), os.SEEK_CUR)
        skip_padding(source, source.tell())
        expanded.seek(0)
        base = newc_inventory(expanded)
        overlay = newc_inventory(source, capture=capture)
    if any(entry["type"] != "file" or not re.fullmatch(r"/usr/lib/fvca/[^/]+", entry["path"])
           for entry in overlay):
        raise ValueError("unexpected file in the signed FVCA composition archive")
    base_types = {entry["path"]: entry["type"] for entry in base}
    if any(base_types.get(parent) != "directory" for parent in ("/usr", "/usr/lib", "/usr/lib/fvca")):
        raise ValueError("the composed initramfs lacks its FVCA policy directory")
    if any(entry["path"] in base_types for entry in overlay):
        raise ValueError("the FVCA composition archive replaces a base initramfs file")
    return {"base_files": base, "configuration_files": overlay}
