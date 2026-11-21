#!/usr/bin/env python3
"""Inventory an authenticated, assembled FVCA boot release off-node."""

import argparse
from compression.zstd import ZstdError
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

import core_image
from file_inventory import composed_initramfs, tree_inventory
import guest_boot_bundle as guest
import hypervisor_gpt as gpt
from image_verity import VERITY_PARTITIONS, extract_partition, read_layout, verify_cms, verify_root, verify_verity
import oci_runtime
from runtime_boot import BOOT_EFI, WORKLOAD_NETWORK_POLICY, WORKLOAD_TRUST_FILES, composition_record, run
import runtime_image
import vm_runtime


POLICY_PREFIX = "/usr/lib/fvca/"
WORKLOAD_FILES = (
    "authorization.json", "authorization.p7s", "deployment.json", "deployment.p7s",
    "derivation.json", "launch.json", "publisher-proof.json", "workload.raw",
)


def snapshot(source, destination):
    if source.is_symlink() or not source.is_file():
        raise ValueError(f"expected a regular release artifact: {source}")
    run("cp", "--reflink=auto", "--sparse=always", "--", source, destination)


def signer(certificate):
    der = run("openssl", "x509", "-in", certificate, "-outform", "DER", capture_output=True).stdout
    return hashlib.sha256(der).hexdigest()


def unpack(work):
    tree = work / "tree"
    run("fsck.erofs", f"--extract={tree}", "--preserve-perms", work / "root")
    return tree


def root_inventory(work, root_hash):
    return {
        "verity_root": root_hash, "data_sha256": guest.sha256(work / "root"),
        "verity_tree_sha256": guest.sha256(work / "verity"), "files": tree_inventory(work / "tree"),
    }


def startup(initrd, work, names, *, optional=()):
    selected = dict.fromkeys(POLICY_PREFIX + name for name in (*names, *optional))
    files = composed_initramfs(initrd, work, selected)
    missing = [name for name in names if not selected[POLICY_PREFIX + name]]
    if missing:
        raise ValueError(f"signed FVCA composition lacks {', '.join(missing)}")
    return {"sha256": guest.sha256(initrd), **files}, {
        path.removeprefix(POLICY_PREFIX): payload for path, payload in selected.items()
    }


def runtime_selection(payload, role, extension, core_hash):
    root_hash = payload.decode("ascii").rsplit("runtime_root=", 1)[-1].removesuffix("\n")
    if (re.fullmatch(r"[0-9a-f]{64}", root_hash) is None or
            payload != composition_record(core_hash, root_hash, role, extension)):
        raise ValueError("the signed initramfs has an unexpected composition")
    return root_hash


def capsule_inventory(bundle, release_certificate):
    _, release = guest.verify(bundle, release_certificate)
    return {
        **release, "release_sha256": guest.sha256(bundle / "release.json"),
        "signature_sha256": guest.sha256(bundle / "release.p7s"),
        "release_signer_sha256": signer(release_certificate),
    }


def installed_root(slot, sector, parts, name, root_hash, signature, certificate, base):
    directory = base / name
    directory.mkdir()
    extract_partition(slot, parts[name], sector, directory / "root")
    extract_partition(slot, parts[name + "_verity"], sector, directory / "verity")
    (directory / "root.p7s").write_bytes(signature)
    verify_root(directory, root_hash, certificate)
    return directory, unpack(directory)


def inspect_slot(args, work):
    if guest.public_key(args.boot_certificate) == guest.public_key(args.guest_release_certificate):
        raise ValueError("Hypervisor Secure Boot and Guest release require distinct authorities")
    slot = work / "slot.raw"
    snapshot(args.slot, slot)
    run("sfdisk", "--verify", "--sector-size", str(args.sector_size), slot, stdout=subprocess.DEVNULL)
    sector, parts = read_layout(slot, gpt.PARTITIONS, sector_size=args.sector_size)
    ids = {name: part["uuid"].lower() for name, part in parts.items()}
    esp = work / "esp"
    extract_partition(slot, parts["esp"], sector, esp)
    files = run("mdir", "-a", "-b", "-s", "-i", esp, "::/", capture_output=True, text=True).stdout.splitlines()
    if sorted(files) != sorted(("::/EFI/", "::/EFI/BOOT/", BOOT_EFI)):
        raise ValueError("the Hypervisor EFI partition contains unreviewed paths")
    uki = work / "boot.efi"
    run("mcopy", "-i", esp, BOOT_EFI, uki)
    sections = core_image.inspect_uki(uki, args.boot_certificate)
    cmdline = sections[".cmdline"]["text"]
    core_hash = core_image.verify_command_line(
        cmdline, f"panic-on-corruption,root-hash-signature={POLICY_PREFIX}{gpt.ROOT_SIGNATURE}", hardened=True,
        devices={"systemd.verity_root_data": f"/dev/disk/by-partuuid/{ids['core']}",
                 "systemd.verity_root_hash": f"/dev/disk/by-partuuid/{ids['core_verity']}"},
    )
    initrd, linux = work / "initrd", work / "linux"
    core_image.extract_uki_section(uki, "initrd", initrd)
    core_image.extract_uki_section(uki, "linux", linux)
    boot, policy = startup(initrd, work, (
        gpt.MANIFEST, gpt.ROOT_SIGNATURE, "hypervisor.composition", "vm-runtime.p7s", "guest-launch", "guest-launch.p7s",
    ))
    selection = "FVCA-HYPERVISOR-SLOT-1\n" + "".join(f"{name}={ids[name]}\n" for name in gpt.PARTITIONS)
    if policy[gpt.MANIFEST] != selection.encode("ascii") or len(set(ids.values())) != len(ids):
        raise ValueError("the signed Hypervisor slot record does not match its GPT")
    runtime_hash = runtime_selection(policy["hypervisor.composition"], "hypervisor", "vm-runtime", core_hash)
    lines = policy["guest-launch"].decode("ascii").splitlines()
    if len(lines) < 2 or lines[0] != "FVCA-GUEST-LAUNCH-1" or not lines[1].startswith("bundle="):
        raise ValueError("invalid signed nested Guest selection")
    guest_hash = lines[1].removeprefix("bundle=")
    certificate = args.boot_certificate
    core_dir, core_tree = installed_root(
        slot, sector, parts, "core", core_hash, policy[gpt.ROOT_SIGNATURE], certificate, work,
    )
    runtime_dir, runtime_tree = installed_root(
        slot, sector, parts, "runtime", runtime_hash, policy["vm-runtime.p7s"], certificate, work,
    )
    runtime_image.verify_tree(runtime_tree, core_tree, core_hash, vm_runtime)
    capsule_dir, capsule = installed_root(
        slot, sector, parts, "guest", guest_hash, policy["guest-launch.p7s"], certificate, work,
    )
    release = capsule_inventory(capsule, args.guest_release_certificate)
    if policy["guest-launch"] != guest.launch_record(capsule, guest_hash, release):
        raise ValueError("nested Guest bytes differ from the signed Hypervisor selection")
    return {
        "role": "hypervisor", "slot_sha256": guest.sha256(slot), "logical_sector_bytes": sector, "partitions": ids,
        "esp": {"sha256": guest.sha256(esp), "paths": [path.removeprefix("::") for path in sorted(files)]},
        "boot_signer_sha256": signer(certificate), "uki_sha256": guest.sha256(uki), "linux_sha256": guest.sha256(linux),
        "initramfs": boot, "core": root_inventory(core_dir, core_hash), "runtime": root_inventory(runtime_dir, runtime_hash),
        "guest_capsule": root_inventory(capsule_dir, guest_hash),
        "guest_release": release,
    }


def inspect_workload(args, work, policy):
    bundle = work / "workload"
    bundle.mkdir(mode=0o700)
    for name in WORKLOAD_FILES:
        snapshot(args.workload_bundle / name, bundle / name)
        (bundle / name).chmod(0o600)
    scope, deployment_der, workload_der = (policy[name] for name in WORKLOAD_TRUST_FILES)
    scope_file = work / "workload-policy.json"
    scope_file.write_bytes(scope)
    deployment_cert, workload_cert = work / "deployment.crt", work / "workload.crt"
    for der, pem in ((deployment_der, deployment_cert), (workload_der, workload_cert)):
        run("openssl", "x509", "-inform", "DER", "-out", pem, input=der)
    run(args.admission_tool, scope_file, deployment_cert, workload_cert, bundle)

    authorization = json.loads((bundle / "authorization.json").read_bytes())
    derivation = json.loads((bundle / "derivation.json").read_bytes())
    deployment = json.loads((bundle / "deployment.json").read_bytes())
    network = policy[WORKLOAD_NETWORK_POLICY]
    expected_network = {"workload": "sha256:" + hashlib.sha256(network).hexdigest()} if network is not None else "none"
    if deployment["network"] != expected_network:
        raise ValueError("workload network differs from the signed Guest boot selection")
    image = bundle / "workload.raw"
    root_dir = work / "workload-root"
    root_dir.mkdir()
    sector, parts = read_layout(image, VERITY_PARTITIONS)
    root_hash = verify_verity(image, sector, parts, workload_cert, root_dir, authorization["verity_root_hash"])
    unpack(root_dir)
    return {
        "guest": deployment["guest"], "service": deployment["service"], "valid_from": deployment["valid_from"],
        "expires": deployment["expires"], "revocation_id": deployment["revocation_id"],
        "security_epoch": deployment["security_epoch"], "provenance": deployment["provenance"],
        "source": derivation["source"], "manifest": derivation["manifest"], "launch_sha256": guest.sha256(bundle / "launch.json"),
        "evidence_sha256": {name: guest.sha256(bundle / name) for name in WORKLOAD_FILES},
        "admission_tool_sha256": guest.sha256(args.admission_tool),
        "root": root_inventory(root_dir, root_hash),
    }


def inspect_guest(args, work):
    boot_key = guest.public_key(args.boot_certificate)
    runtime_key = guest.public_key(args.runtime_certificate)
    if boot_key == runtime_key:
        raise ValueError("Guest Secure Boot and runtime require distinct authorities")
    guest.require_authority(args.guest_release_certificate, None, None, boot_key, runtime_key)
    if args.bundle.is_symlink() or {path.name for path in args.bundle.iterdir()} != set(guest.BUNDLE_FILES):
        raise ValueError("unexpected Service Guest direct-boot bundle contents")
    bundle = work / "bundle"
    bundle.mkdir()
    for name in guest.BUNDLE_FILES:
        snapshot(args.bundle / name, bundle / name)
    release = capsule_inventory(bundle, args.guest_release_certificate)
    core_dir, runtime_dir = work / "core", work / "runtime"
    core_dir.mkdir()
    runtime_dir.mkdir()
    certificate = args.boot_certificate
    core_hash = core_image.verify(bundle / "core.raw", certificate, certificate, core_dir, direct_boot=True)
    uki = core_dir / "boot.efi"
    if guest.sha256(uki) != release["files"]["boot.efi"] or core_hash != release["core_root"]:
        raise ValueError("the release and the core disk select different Guest UKIs or roots")
    for name in ("initrd", "linux"):
        extracted = work / name
        core_image.extract_uki_section(uki, name, extracted)
        if guest.sha256(extracted) != release["files"][name]:
            raise ValueError(f"the released {name} differs from its signed UKI section")
    cmdline = (bundle / "cmdline").read_text(encoding="ascii")
    if core_image.inspect_uki(uki, certificate)[".cmdline"]["text"] != cmdline.removesuffix("\n"):
        raise ValueError("the release command line differs from the Guest UKI")
    required = (
        "service-guest.composition", "oci-runtime.p7s", "direct-boot.cmdline", "direct-verity.der", "direct-root.p7s",
    )
    if args.workload_bundle is not None:
        required += WORKLOAD_TRUST_FILES
    boot, policy = startup(bundle / "initrd", work, required, optional=(WORKLOAD_NETWORK_POLICY,))
    expected_runtime = runtime_selection(policy["service-guest.composition"], "service-guest", "oci-runtime", core_hash)
    der = run("openssl", "x509", "-in", certificate, "-outform", "DER", capture_output=True).stdout
    if (policy["direct-boot.cmdline"] != cmdline.encode("ascii") or policy["direct-verity.der"] != der
            or policy["direct-root.p7s"] != (core_dir / "root.p7s").read_bytes()):
        raise ValueError("direct-boot trust records differ from the verified Guest root and command line")
    core_tree = unpack(core_dir)
    runtime_hash = runtime_image.verify_payload(
        bundle / "runtime.raw", args.runtime_certificate, core_tree, core_hash, runtime_dir, oci_runtime,
    )
    if runtime_hash != expected_runtime or runtime_hash != release["runtime_root"]:
        raise ValueError("the Guest release, UKI and OCI runtime select different roots")
    authorization = work / "runtime-authorization.p7s"
    authorization.write_bytes(policy["oci-runtime.p7s"])
    verify_cms(runtime_dir / "roothash", authorization, certificate)
    report = {
        "role": "service-guest", "guest_release": release, "boot_signer_sha256": signer(certificate),
        "runtime_signer_sha256": signer(args.runtime_certificate), "initramfs": boot,
        "core": root_inventory(core_dir, core_hash), "runtime": root_inventory(runtime_dir, runtime_hash),
    }
    if args.workload_bundle is not None:
        report["workload"] = inspect_workload(args, work, policy)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    common = argparse.ArgumentParser(add_help=False)
    for option in ("boot-certificate", "guest-release-certificate", "output"):
        common.add_argument(f"--{option}", type=lambda path: Path(path).absolute(), required=True)
    mode = parser.add_subparsers(dest="role", required=True)
    host = mode.add_parser("hypervisor", parents=[common])
    host.add_argument("--slot", type=Path, required=True, help="immutable Hypervisor GPT disk")
    host.add_argument("--sector-size", type=int, choices=(4096, 512), default=4096)
    service_guest = mode.add_parser("service-guest", parents=[common])
    service_guest.add_argument("--bundle", type=Path, required=True)
    service_guest.add_argument("--runtime-certificate", type=Path, required=True)
    service_guest.add_argument("--workload-bundle", type=Path, help="authorized workload from the Guest's data volume")
    service_guest.add_argument("--admission-tool", type=lambda path: Path(path).absolute(),
                               help="reviewed fvca-workload-admission binary")
    args = parser.parse_args()
    if args.role == "service-guest" and (args.workload_bundle is None) != (args.admission_tool is None):
        parser.error("--workload-bundle and --admission-tool must be supplied together")
    try:
        if args.output.exists() or args.output.is_symlink():
            raise ValueError("use a new inventory file")
        with tempfile.TemporaryDirectory(prefix=".fvca-boot-inventory-", dir=args.output.parent) as directory:
            work = Path(directory)
            report = inspect_slot(args, work) if args.role == "hypervisor" else inspect_guest(args, work)
            result = work / "boot-inventory.json"
            with result.open("x", encoding="ascii") as output:
                json.dump({"schema": "fvca-boot-inventory-v1", **report}, output, sort_keys=True, separators=(",", ":"))
                output.write("\n")
            args.output.hardlink_to(result)
    except (OSError, KeyError, ValueError, RuntimeError, ZstdError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"FVCA boot inventory failed: {error}\n")
    print(f"Inventoried assembled {args.role} boot, including "
          f"{len(report['initramfs']['configuration_files'])} signed configuration files")


if __name__ == "__main__":
    main()
