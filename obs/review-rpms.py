#!/usr/bin/env python3
"""Record independently verified Fedora RPM inputs for an FVCA role."""

import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
from xml.etree import ElementTree as ET


RUNTIMES = {"hypervisor": "vm-runtime", "service-guest": "oci-runtime"}
FEDORA_45_KEY = "4f50a6114cd5c6976a7f1179655a4b02f577861e"
RPM_COMPONENT = r"[A-Za-z0-9._+~^]+"
RPM_QUERY = (
    "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t"
    "%{SIGMD5}\t%{SHA256HEADER}\t%{SOURCERPM}\t%{LICENSE:json}\n"
)


def manifest(path, name, format_):
    raw = path.read_bytes()
    if path.suffix == ".gz":
        raw = gzip.decompress(raw)
    data = json.loads(raw)
    config = data["config"]
    expected = {"name": name, "distribution": "fedora", "release": "45",
                "architecture": "x86-64", "output_format": format_}
    if data["manifest_version"] != 1 or any(config[key] != value for key, value in expected.items()):
        raise ValueError(f"{path.name} is not the expected Fedora 45 {name} manifest")
    rpms = {}
    key_record = None
    for package in data["packages"]:
        package_name, evr, arch = (package[key] for key in ("name", "version", "architecture"))
        if package["type"] != "rpm":
            raise ValueError(f"unexpected package type in {path.name}")
        if package_name == "gpg-pubkey":
            if key_record is not None or arch or not re.fullmatch(f"{FEDORA_45_KEY}-[0-9a-f]{{8}}", evr):
                raise ValueError(f"unexpected RPM keyring entry in {path.name}")
            key_record = evr
            continue
        version = re.fullmatch(rf"(?:(0|[1-9][0-9]*):)?({RPM_COMPONENT})-({RPM_COMPONENT})", evr)
        if (version is None or not re.fullmatch(r"[A-Za-z0-9._+-]+", package_name)
                or arch not in ("x86_64", "noarch")):
            raise ValueError(f"invalid RPM identity in {path.name}: {package_name} {evr} {arch}")
        epoch, upstream, release = version.groups()
        if (package_name, arch) in rpms:
            raise ValueError(f"duplicate RPM name and architecture in {path.name}: {package_name} {arch}")
        rpms[package_name, arch] = (package_name, epoch or "0", upstream, release, arch)
    if not rpms:
        raise ValueError(f"empty RPM manifest: {path.name}")
    return rpms, {"sha256": hashlib.sha256(raw).hexdigest(), "rpm_keyring_record": key_record}


def worker_records(path, role, identities):
    raw = path.read_bytes()
    document = ET.fromstring(raw)
    if (document.tag != "buildinfo" or document.get("package") != f"fvca-{role}"
            or document.findtext("arch") != "x86_64"):
        raise ValueError("the OBS build environment is for a different role or architecture")
    records = {}
    for entry in document.findall("bdep"):
        identity = (entry.get("name"), entry.get("epoch", "0"), entry.get("version"),
                    entry.get("release"), entry.get("arch"))
        if identity not in identities:
            continue
        identifier = entry.attrib["hdrmd5"]
        if (entry.get("project") != "Fedora:45" or entry.get("repository") not in ("standard", "update")
                or not re.fullmatch(r"[0-9a-f]{32}", identifier) or identity in records):
            raise ValueError(f"unexpected OBS worker origin for {identity[0]}")
        records[identity] = {"repository": entry.get("repository"), "hdrmd5": identifier}
    missing = identities - records.keys()
    if missing:
        names = ", ".join(f"{name} {epoch}:{version}-{release}.{arch}"
                          for name, epoch, version, release, arch in sorted(missing))
        raise ValueError(f"core RPMs missing from the recorded OBS worker inputs: {names}")
    return records, {
        "project": document.attrib["project"], "repository": document.attrib["repository"],
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def obs_package_id(package, legacy, header):
    if legacy == "(none)" and re.fullmatch(r"[0-9a-f]{64}", header):
        return header[:32]
    if not re.fullmatch(r"[0-9a-f]{32}", legacy):
        raise ValueError("RPM lacks the identifier used by OBS")
    # The legacy OBS identifier covers the main header and payload. Calculate
    # it from the Fedora-verified archive, outside the mutable signature header.
    with package.open("rb") as stream:
        stream.seek(96)
        magic, count, size = struct.unpack(">4s4xII", stream.read(16))
        if magic != b"\x8e\xad\xe8\x01":
            raise ValueError("invalid RPM signature header")
        offset = (112 + count * 16 + size + 7) & ~7
        stream.seek(offset)
        if stream.read(4) != magic:
            raise ValueError("invalid RPM main header")
        stream.seek(offset)
        actual = hashlib.file_digest(stream, lambda: hashlib.md5(usedforsecurity=False)).hexdigest()
    if actual != legacy:
        raise ValueError("RPM legacy OBS identifier does not match its header and payload")
    return actual


def review_archives(args, work, core, runtime, worker):
    options = ["--noplugins", "--dbpath", str(work / "rpmdb"), "--define", "_keyring rpmdb",
               "--define", "_pkgverify_level all", "--define", "_pkgverify_flags 0x20100"]
    keys = ["rpmkeys", *options]
    subprocess.run([*keys, "--import", args.fedora_key], check=True)
    loaded = subprocess.check_output([*keys, "--list"], text=True).splitlines()
    if len(loaded) != 1 or not loaded[0].startswith(FEDORA_45_KEY + " "):
        raise ValueError("the isolated RPM keyring must contain only the reviewed Fedora 45 key")
    packages = []
    for identity in sorted(core | runtime):
        name, epoch, version, release, arch = identity
        filename = f"{name}-{version}-{release}.{arch}.rpm"
        archive = args.rpm_directory / filename
        if archive.is_symlink() or not archive.is_file():
            raise ValueError(f"missing regular RPM archive: {filename}")
        snapshot = work / filename
        shutil.copyfile(archive, snapshot)
        verification = subprocess.run([*keys, "--checksig", snapshot], stdout=subprocess.DEVNULL)
        if verification.returncode:
            raise ValueError(f"Fedora signature or package digest verification failed for {filename}")
        output = subprocess.check_output(["rpm", *options, "-qp", "--qf", RPM_QUERY, snapshot], text=True)
        *rpm_identity, legacy, header, source_rpm, license_json = output.rstrip("\n").split("\t")
        if tuple(rpm_identity) != identity:
            raise ValueError(f"RPM header identity differs from the reviewed manifest: {filename}")
        origin = worker.get(identity)
        if origin is not None and obs_package_id(snapshot, legacy, header) != origin["hdrmd5"]:
            raise ValueError(f"Fedora RPM differs from the OBS worker input: {filename}")
        with snapshot.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        snapshot.unlink()
        packages.append({
            "nevra": f"{name}-{epoch}:{version}-{release}.{arch}",
            "sha256": digest, "source_rpm": source_rpm, "license": json.loads(license_json),
            "transactions": [label for label, members in (("core", core), (RUNTIMES[args.role], runtime))
                             if identity in members],
            "obs_core_input": origin,
        })
    return packages


def review(args, work):
    core, core_input = manifest(args.core_manifest, f"fvca-obs-{args.role}", "disk")
    runtime, runtime_input = manifest(args.runtime_manifest, RUNTIMES[args.role], "sysext")
    if any(core[key] != runtime[key] for key in core.keys() & runtime.keys()):
        raise ValueError("shared core and runtime RPM versions differ")
    core, runtime = set(core.values()), set(runtime.values())
    records, worker = worker_records(args.buildenv, args.role, core)
    packages = review_archives(args, work, core, runtime, records)
    report = {
        "schema": "fvca-fedora-rpm-review-v1", "role": args.role, "fedora_release": "45",
        "fedora_signer_fingerprint": FEDORA_45_KEY, "core_manifest": core_input,
        "runtime_manifest": runtime_input, "obs_buildenv": worker, "packages": packages,
    }
    result = work / "review.json"
    result.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.output.hardlink_to(result)
    print(f"Verified {len(packages)} Fedora archives and matched {len(core)} core RPMs to the OBS worker record")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=RUNTIMES)
    for name in ("core-manifest", "runtime-manifest", "buildenv", "rpm-directory", "fedora-key", "output"):
        parser.add_argument(f"--{name}", required=True, type=lambda value: Path(value).absolute())
    args = parser.parse_args()
    try:
        with tempfile.TemporaryDirectory(prefix=".fvca-rpm-review-", dir=args.output.parent) as work:
            review(args, Path(work))
    except (OSError, ValueError, KeyError, TypeError, ET.ParseError, struct.error,
            subprocess.CalledProcessError) as error:
        parser.exit(1, f"Fedora RPM review failed: {error}\n")


if __name__ == "__main__":
    main()
