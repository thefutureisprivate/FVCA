"""Sign the exact UKI-derived inputs and machine definition for direct boot."""

import hashlib
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

from image_verity import VERITY_PARTITIONS, read_layout, verify_cms, verify_verity
from runtime_boot import run
from workload_oci import parse_json


MACHINE = Path(__file__).resolve().parents[1] / "policy/guest-direct-boot.xml"
ASSETS = ("boot.efi", "linux", "initrd", "cmdline", "domain.xml", "core.raw", "runtime.raw")
BUNDLE_FILES = (*ASSETS, "release.json", "release.p7s")
SCHEMA = "fvca-service-guest-direct-boot-1"
SERVICE_GUEST_ID = "e629aa43-af11-47c6-aedc-a2dc47f1cc3a"


def public_key(certificate):
    return run("openssl", "x509", "-in", certificate, "-pubkey", "-noout", capture_output=True).stdout


def require_authority(release, deployment, workload, boot_key, runtime_key):
    release_key = public_key(release)
    if release_key in (boot_key, runtime_key) or any(
        release_key == public_key(certificate) for certificate in (deployment, workload) if certificate is not None
    ):
        raise ValueError("the direct-boot release authority requires its own signing key")


def sha256(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def verify(bundle, certificate):
    manifest = bundle / "release.json"
    signature = bundle / "release.p7s"
    for path in (manifest, signature):
        if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 16 * 1024:
            raise ValueError(f"invalid boot bundle {path.name}")
    verify_cms(manifest, signature, certificate)
    release = parse_json(manifest.read_bytes())
    if (not isinstance(release, dict) or release.keys() != {"schema", "core_root", "runtime_root", "files"}
            or release["schema"] != SCHEMA or not isinstance(release["files"], dict)
            or release["files"].keys() != set(ASSETS)):
        raise ValueError("invalid Service Guest direct-boot release")
    if any(not isinstance(release[key], str) or re.fullmatch(r"[0-9a-f]{64}", release[key]) is None
           for key in ("core_root", "runtime_root")):
        raise ValueError("invalid Service Guest composition identity")
    for name in ASSETS:
        path = bundle / name
        if path.is_symlink() or not path.is_file() or sha256(path) != release["files"][name]:
            raise ValueError(f"boot bundle file {name} does not match the signed release")
    cmdline = (bundle / "cmdline").read_bytes().decode("ascii")
    expected_root = f"roothash={release['core_root']}"
    if (not cmdline.endswith("\n") or not 1 < len(cmdline) <= 2048
            or any(not " " <= character <= "~" for character in cmdline[:-1])
            or [part for part in cmdline.split() if part.startswith("roothash=")] != [expected_root]):
        raise ValueError("direct-boot command line has an unexpected core binding")
    try:
        domain = ET.parse(bundle / "domain.xml").getroot()
    except ET.ParseError as error:
        raise ValueError("invalid direct-boot domain XML") from error
    expected = ET.parse(MACHINE).getroot()
    expected.find("./os/cmdline").text = cmdline.removesuffix("\n")
    if ET.tostring(domain) != ET.tostring(expected):
        raise ValueError("direct-boot domain differs from the approved machine definition")
    return cmdline.removesuffix("\n"), release


def select_image(image, verity_certificate, release_certificate, work):
    sector, parts = read_layout(image, VERITY_PARTITIONS)
    root = verify_verity(image, sector, parts, verity_certificate, work)
    tree = work / "tree"
    run("fsck.erofs", f"--extract={tree}", "--preserve-perms", work / "root")
    if {entry.name for entry in tree.iterdir()} != set(BUNDLE_FILES):
        raise ValueError("unexpected Guest boot disk contents")
    _, release = verify(tree, release_certificate)
    digests = release["files"] | {name: sha256(tree / name) for name in ("release.json", "release.p7s")}
    checksums = "".join(f"{digests[name]}  {name}\n" for name in BUNDLE_FILES)
    return root, (f"FVCA-GUEST-LAUNCH-1\nbundle={root}\ncore={release['core_root']}\n"
                  f"runtime={release['runtime_root']}\n{checksums}").encode("ascii")


def publish(args, work, disk, uki, runtime, cmdline, core_hash, runtime_hash):
    bundle = work / "boot-bundle"
    bundle.mkdir(mode=0o700)
    uki.rename(bundle / "boot.efi")
    disk.rename(bundle / "core.raw")
    runtime.rename(bundle / "runtime.raw")
    uki = bundle / "boot.efi"
    run("sbverify", "--cert", args.boot_certificate, uki)
    sections = json.loads(run("ukify", "--json=short", "inspect", uki, capture_output=True).stdout)
    if sections.get("_profiles") or sections[".cmdline"]["text"] != cmdline:
        raise ValueError("the signed direct-boot UKI has a different command line")
    for section in ("linux", "initrd"):
        run("ukify", f"--section=.{section}:binary@{bundle / section}", "inspect", uki,
            capture_output=True)
    (bundle / "cmdline").write_text(cmdline + "\n", encoding="ascii")
    machine = ET.parse(MACHINE)
    machine.find("./os/cmdline").text = cmdline
    machine.write(bundle / "domain.xml", encoding="UTF-8")

    release = {
        "schema": SCHEMA,
        "core_root": core_hash,
        "runtime_root": runtime_hash,
        "files": {name: sha256(bundle / name) for name in ASSETS},
    }
    manifest = bundle / "release.json"
    signature = bundle / "release.p7s"
    manifest.write_text(json.dumps(release, sort_keys=True, separators=(",", ":")) + "\n", encoding="ascii")
    run("openssl", "cms", "-sign", "-binary", "-noattr", "-nocerts", "-outform", "DER", "-in", manifest,
        "-signer", args.release_certificate, "-inkey", args.release_key, "-out", signature)
    verify(bundle, args.release_certificate)
    run("mv", "--no-clobber", "--no-target-directory", "--", bundle, args.direct_boot)
    if bundle.exists():
        raise FileExistsError(args.direct_boot)
