#!/usr/bin/env python3
"""Compare the authenticated payloads of an FVCA OBS core and an independent rebuild."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

import core_image
from file_inventory import initramfs_inventory, tree_inventory
from guest_boot_bundle import public_key, sha256
from runtime_boot import run
from workload_oci import json_bytes, parse_json, read_bytes


ROLE_MARKERS = {"hypervisor": "/usr/lib/fvca/activate-runtime",
                "service-guest": "/usr/lib/fvca/activate-oci-runtime"}
UNSIGNED = ("root_erofs", "verity_tree", "unsigned_uki", "unsigned_linux", "initramfs")
MANIFEST_LIMIT = 1024 * 1024
SIGNATURE_LINE = re.compile(r"^signature [1-9][0-9]*$", re.MULTILINE)


def unsigned_pe_digest(path):
    listing = run("sbverify", "--list", path, capture_output=True, text=True).stdout
    signatures = SIGNATURE_LINE.findall(listing)
    for _ in signatures:
        run("sbattach", "--remove", path)
    if signatures:
        remaining = run("sbverify", "--list", path, capture_output=True, text=True).stdout
        if SIGNATURE_LINE.search(remaining):
            raise ValueError("could not remove the PE signatures for payload comparison")
    return sha256(path)


def packages(path, role):
    data = read_bytes(path, MANIFEST_LIMIT)
    manifest = parse_json(data)
    expected = {"name": f"fvca-obs-{role}", "architecture": "x86-64", "distribution": "fedora",
                "release": "45", "output_format": "disk"}
    if (manifest["manifest_version"] != 1
            or any(manifest["config"].get(key) != value for key, value in expected.items())):
        raise ValueError("expected the selected OBS core package manifest")
    selected, keyring = {}, []
    for package in manifest["packages"]:
        name, arch, version = (package[key] for key in ("name", "architecture", "version"))
        if (package["type"] != "rpm" or not isinstance(name, str) or not name
                or not isinstance(version, str) or not version):
            raise ValueError("invalid RPM transaction entry in the core manifest")
        if name == "gpg-pubkey":
            keyring.append(version)
            continue
        if arch not in ("x86_64", "noarch") or (name, arch) in selected:
            raise ValueError("unexpected architecture or duplicate RPM transaction entry")
        selected[name, arch] = version
    if not selected:
        raise ValueError("the core package manifest is empty")
    return selected, sorted(keyring), hashlib.sha256(data).hexdigest()


def inspect(image, certificate, role, work):
    if image.is_symlink() or not image.is_file():
        raise ValueError("expected a regular core image")
    work.mkdir(mode=0o700)
    snapshot = work / "core.raw"
    run("cp", "--reflink=auto", "--sparse=always", "--", image, snapshot)
    rpms, keyring, manifest = packages(image.with_suffix(".manifest"), role)
    root_hash = core_image.verify(snapshot, certificate, certificate, work)
    uki = work / "boot.efi"
    for section in ("linux", "initrd"):
        core_image.extract_uki_section(uki, section, work / section)
    signed_uki, linux = sha256(uki), sha256(work / "linux")
    unsigned_uki = unsigned_pe_digest(uki)
    unsigned_linux = unsigned_pe_digest(work / "linux")

    initial = initramfs_inventory(work / "initrd")
    markers = {entry["path"] for entry in initial if entry["type"] == "file"} & set(ROLE_MARKERS.values())
    if markers != {ROLE_MARKERS[role]}:
        raise ValueError("the authenticated initramfs has an unexpected role")
    tree = work / "extracted"
    run("fsck.erofs", f"--extract={tree}", "--preserve-perms", work / "root")
    core = tree_inventory(tree)
    result = {
        "disk": sha256(snapshot), "signed_uki": signed_uki, "unsigned_uki": unsigned_uki,
        "root_erofs": sha256(work / "root"), "verity_tree": sha256(work / "verity"),
        "root_hash": root_hash, "root_signature": sha256(work / "root.p7s"),
        "embedded_linux": linux, "unsigned_linux": unsigned_linux, "initramfs": sha256(work / "initrd"),
        "package_manifest": manifest, "rpm_keyring_records": keyring,
    }
    return result, rpms, core, initial


def file_changes(reference, rebuilt):
    first, second = ({record["path"]: record for record in items} for items in (reference, rebuilt))
    return {
        "reference_only": sorted(first.keys() - second.keys()),
        "rebuild_only": sorted(second.keys() - first.keys()),
        "changed": [{"path": path, "reference": first[path], "rebuild": second[path]}
                    for path in sorted(first.keys() & second.keys()) if first[path] != second[path]],
    }


def compare(args, work):
    if public_key(args.reference_certificate) == public_key(args.rebuilt_certificate):
        raise ValueError("the reference and rebuild must use independent signing keys")
    reference, original, core, initrd = inspect(
        args.reference, args.reference_certificate, args.role, work / "reference",
    )
    rebuilt, rebuilt_rpms, other_core, other_initrd = inspect(
        args.rebuilt, args.rebuilt_certificate, args.role, work / "rebuilt",
    )
    payloads = {name: reference[name] == rebuilt[name] for name in UNSIGNED}
    packages_changed = [{"name": name, "architecture": arch, "reference": original.get((name, arch)),
                         "rebuild": rebuilt_rpms.get((name, arch))}
                        for name, arch in sorted(original.keys() | rebuilt_rpms.keys())
                        if original.get((name, arch)) != rebuilt_rpms.get((name, arch))]
    report = {
        "schema": "fvca-core-rebuild-comparison-v1", "role": args.role,
        "reference_sha256": reference, "rebuilt_sha256": rebuilt,
        "unsigned_component_matches": payloads, "unsigned_payloads_match": all(payloads.values()),
        "rpm_nevra_matches": not packages_changed, "rpm_differences": packages_changed,
        "core_file_differences": file_changes(core, other_core),
        "initramfs_file_differences": file_changes(initrd, other_initrd),
    }
    result = work / "comparison.json"
    result.write_bytes(json_bytes(report))
    args.output.hardlink_to(result)
    print(f"FVCA_CORE_REBUILD_COMPARED {args.role} unsigned_match={all(payloads.values())} "
          f"rpm_nevra_match={not packages_changed}")
    return all(payloads.values()) and not packages_changed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=ROLE_MARKERS)
    for name in ("reference", "reference-certificate", "rebuilt", "rebuilt-certificate", "output"):
        parser.add_argument(f"--{name}", required=True, type=lambda path: Path(path).absolute())
    args = parser.parse_args()
    try:
        if args.output.exists() or args.output.is_symlink():
            raise ValueError("use a new comparison report path")
        with tempfile.TemporaryDirectory(prefix=".fvca-core-rebuild-", dir=args.output.parent) as directory:
            if not compare(args, Path(directory)):
                parser.exit(2)
    except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"FVCA core rebuild comparison failed: {error}\n")


if __name__ == "__main__":
    main()
