"""Compose role boot images from verified FVCA artifacts."""

import json
from pathlib import Path
import subprocess

from image_verity import VERITY_PARTITIONS, read_layout


TOOLS = Path(__file__).resolve().parent
PARTITIONS = {"esp": "c12a7328-f81f-11d2-ba4b-00a0c93ec93b", **VERITY_PARTITIONS}
BOOT_EFI = "::/EFI/BOOT/BOOTX64.EFI"
DISABLE_AUTOMATIC_EXTENSIONS = (
    "rd.systemd.sysext=no", "rd.systemd.confext=no", "systemd.sysext=no", "systemd.confext=no",
    "rd.systemd.mask=systemd-sysext.socket", "rd.systemd.mask=systemd-confext.socket",
    "systemd.mask=systemd-sysext.socket", "systemd.mask=systemd-confext.socket",
)
WORKLOAD_TRUST_FILES = ("workload-policy.json", "workload-deployment.der", "workload-verity.der")
BASE_ROOT_OPTIONS = "panic-on-corruption,root-hash-signature=auto"
DIRECT_ROOT_OPTIONS = "panic-on-corruption,root-hash-signature=/usr/lib/fvca/direct-root.p7s"
DIRECT_BOOT_FILES = ("direct-boot.cmdline", "direct-verity.der", "direct-root.p7s", "direct-boot-ready")
GUEST_LAUNCH_FILES = ("guest-launch", "guest-launch.p7s")
GUEST_VM_SETTINGS = "guest-vm-settings"
GUEST_VM_SUPPORT = Path("usr/lib/fvca/guest-vm-settings-v2")
GUEST_CONFIG_ARGUMENT = "fvca.guest_config"
GUEST_CONFIG_KEY = "guest-configuration-key"
GUEST_CONFIG_KEY_ARGUMENT = "fvca.guest_config_key"
GUEST_CONFIG_CHANGE_SUPPORT = Path("usr/lib/fvca/guest-configuration-change-v1")
MANAGEMENT_POLICY = "management.json"
MANAGEMENT_ARGUMENT = "fvca.management"
MANAGEMENT_ADDRESS_ARGUMENT = "fvca.management_address"
MANAGEMENT_POLICY_SUPPORT = Path("usr/lib/fvca/management-policy-v1")
MANAGEMENT_SUPPORT = Path("usr/lib/fvca/management-services-v1")
HOST_NETWORK_ARGUMENT = "fvca.host_network"
HOST_NETWORK_POLICY = "host-network"
HOST_NETWORK_SUPPORT = Path("usr/lib/fvca/host-network-v1")
HOST_WORKLOAD_ARGUMENT = "fvca.host_workload"
HOST_WORKLOAD_POLICY = "host-workload"
HOST_WORKLOAD_GUEST = "host-workload-guest"
HOST_WORKLOAD_SUPPORT = Path("usr/lib/fvca/host-workload-network-v1")
WORKLOAD_NETWORK_ARGUMENT = "fvca.workload_network"
WORKLOAD_NETWORK_POLICY = "workload-network"
WORKLOAD_NETWORK_SUPPORT = Path("usr/lib/fvca/workload-network-v1")
SECURE_KERNEL_OPTIONS = ("module.sig_enforce=1", "lockdown=integrity", "debugfs=off")
KERNEL_POLICY_SUPPORT = "usr/lib/fvca/kernel-policy-v1"
KERNEL_SERVICE_POLICY = (
    Path("usr/lib/systemd/system.conf.d/60-fvca-raw-io.conf"),
    Path("usr/lib/systemd/system/service.d/60-fvca-kernel-observability.conf"),
)


def add_kernel_policy(cmdline, options):
    reserved = {option.partition("=")[0] for option in options}
    if any(option.partition("=")[0] in reserved for option in cmdline.split()):
        raise ValueError("the shared core already supplies a role kernel policy option")
    return " ".join((cmdline, *options))


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def verify_initrd(initrd, uname, required, forbidden, role):
    with subprocess.Popen(["zstd", "-dc", initrd], stdout=subprocess.PIPE) as decompressor:
        with decompressor.stdout:
            entries = run("cpio", "--quiet", "-it", stdin=decompressor.stdout, capture_output=True, text=True)
        if decompressor.wait():
            raise ValueError(f"could not decompress the {role} initramfs")
    paths = entries.stdout.splitlines()
    required = (*required, *map(str, KERNEL_SERVICE_POLICY))
    if any(paths.count(path) != 1 for path in required):
        raise ValueError(f"expected the {role} initramfs with its activation units")
    if f"usr/lib/modules/{uname}/modules.dep" not in paths:
        raise ValueError(f"the {role} initramfs does not match the core kernel")
    if set(forbidden).intersection(paths):
        raise ValueError(f"expected an unconfigured {role} initramfs")


def composition_archive(work, boot_key, boot_certificate, core_hash, runtime_hash, role, runtime, *, extra=()):
    root_hash_file = work / "runtime.roothash"
    root_hash_file.write_text(runtime_hash, encoding="ascii")
    files = work / "usr/lib/fvca"
    files.mkdir(parents=True)
    composition = files / f"{role}.composition"
    composition.write_text(
        f"FVCA-DEVELOPMENT-1\nrole={role}\nruntime={runtime}\n"
        f"core={core_hash}\nruntime_root={runtime_hash}\n",
        encoding="ascii",
    )
    signature = files / f"{runtime}.p7s"
    # The runtime artifact passed independent signer verification. This signature
    # authorizes its root on the disposable kernel's existing verity keyring.
    run("openssl", "cms", "-sign", "-binary", "-nocerts", "-noattr", "-outform", "DER",
        "-in", root_hash_file, "-signer", boot_certificate, "-inkey", boot_key, "-out", signature)
    paths = [composition, signature]
    for filename, payload in extra:
        entry = files / filename
        entry.write_bytes(payload)
        paths.append(entry)
    payload = b"".join(bytes(path.relative_to(work)) + b"\0" for path in paths)
    archive = work / "composition.cpio"
    for path in paths:
        path.chmod(0o644)
    with archive.open("wb") as output:
        run("cpio", "--quiet", "-o", "-0", "--format=newc", "--reproducible", "--owner=0:0",
            input=payload, stdout=output, cwd=work)
    return archive


def prepare_core(args, work):
    prepared = work / "core"
    run("python3", TOOLS / "verify-base.py", args.core, args.boot_certificate, "--extract-root", prepared)
    for path in KERNEL_SERVICE_POLICY:
        policy = prepared / "root" / path
        if policy.is_symlink() or not policy.is_file() or policy.read_bytes() != (
            TOOLS.parent / "mkosi.os-policy" / path
        ).read_bytes():
            raise ValueError(f"the verified core lacks the FVCA kernel service policy at {path}")
    core_hash = (prepared / "roothash").read_text(encoding="ascii").strip()
    sector_size, partitions = read_layout(args.core, PARTITIONS)
    offset = partitions["esp"]["start"] * sector_size
    base_uki = work / "base.efi"
    run("mcopy", "-i", f"{args.core}@@{offset}", BOOT_EFI, base_uki)
    run("sbverify", "--cert", args.boot_certificate, base_uki)
    metadata = json.loads(run("ukify", "--json=short", "inspect", base_uki, capture_output=True).stdout)
    cmdline = metadata[".cmdline"]["text"]
    if [part for part in cmdline.split() if part.startswith("roothash=")] != [f"roothash={core_hash}"]:
        raise ValueError("the signed core UKI does not match the prepared root")
    for section in ("linux", "osrel"):
        run("ukify", f"--section=.{section}:binary@{work / section}", "inspect", base_uki,
            stdout=subprocess.DEVNULL)
    uname = metadata[".uname"]["text"]
    return prepared, core_hash, offset, cmdline, uname


def build_uki(args, work, cmdline, uname, composition, options):
    uki = work / "composed.efi"
    run("ukify", "build", "--config=/dev/null", f"--linux={work / 'linux'}",
        f"--os-release=@{work / 'osrel'}", f"--uname={uname}",
        f"--cmdline={cmdline}",
        f"--initrd={args.initrd}", f"--initrd={composition}",
        f"--secureboot-private-key={args.boot_key}", f"--secureboot-certificate={args.boot_certificate}",
        *options, "--no-sign-kernel", f"--output={uki}")
    return uki


def write_disk(args, work, offset, cmdline, uname, composition, *, uki_options=(), direct_boot=False):
    uki = build_uki(args, work, cmdline, uname, composition, uki_options)

    disk = work / "composed.raw"
    run("cp", "--reflink=auto", "--sparse=always", "--", args.core, disk)
    run("mdel", "-i", f"{disk}@@{offset}", BOOT_EFI)
    run("mcopy", "-i", f"{disk}@@{offset}", uki, BOOT_EFI)
    verify_options = ("--direct-boot",) if direct_boot else ()
    run("python3", TOOLS / "verify-base.py", disk, args.boot_certificate, *verify_options)
    return disk, uki
