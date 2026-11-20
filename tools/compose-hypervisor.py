#!/usr/bin/env python3
"""Assemble a Secure Boot Hypervisor development disk without rewriting its core."""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
from uuid import UUID

import backup_destination
import guest_boot_bundle
import hypervisor_gpt
from image_verity import VERITY_PARTITIONS, read_layout, verify_verity
from runtime_boot import (
    DIRECT_BOOT_FILES, DISABLE_AUTOMATIC_EXTENSIONS, GUEST_LAUNCH_FILES, WORKLOAD_TRUST_FILES,
    composition_archive, prepare_core, run, verify_initrd, write_disk,
)
from runtime_image import verify as verify_runtime
import vm_runtime


PCR_POLICY_REF = "fvca-host-storage"
ROLE_BOOT_OPTIONS = ("kvm_intel.nested=0", *DISABLE_AUTOMATIC_EXTENSIONS)
ACTIVATION_FILES = (
    "etc/systemd/system/systemd-confext-initrd.service",
    "etc/systemd/system/systemd-confext-sysroot.service",
    "etc/systemd/system/systemd-sysext-initrd.service",
    "etc/systemd/system/systemd-sysext-sysroot.service",
    "usr/lib/fvca/activate-runtime",
    "usr/lib/systemd/system/fvca-activate-runtime.service",
    "usr/lib/systemd/system/initrd-parse-etc.service.d/20-fvca-runtime.conf",
    "usr/lib/systemd/system/initrd-switch-root.service.d/20-fvca-runtime.conf",
)


def storage_selection(path):
    content = path.read_bytes()
    uuid = r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"
    match = re.fullmatch(
        rf"FVCA-HOST-STORAGE-3\nunlock=(development-passphrase|tpm2-pin)\n"
        rf"member_a=({uuid}),({uuid})\nmember_b=({uuid}),({uuid})\n"
        rf"filesystem=btrfs\nfilesystem_uuid={uuid}\n"
        r"(?:token_a=(?:[0-9]|[12][0-9]|3[01]),([0-9a-f]{64})\n"
        r"token_b=(?:[0-9]|[12][0-9]|3[01]),([0-9a-f]{64})\n)?",
        content.decode("ascii"),
    )
    if match is None:
        raise ValueError("invalid Hypervisor storage selection")
    unlock, partition_a, luks_a, partition_b, luks_b, digest_a, digest_b = match.groups()
    if partition_a == partition_b or luks_a == luks_b:
        raise ValueError("storage selection must name distinct partitions and LUKS2 volumes")
    if (unlock == "tpm2-pin") != (digest_a is not None) or (digest_a is not None and digest_a == digest_b):
        raise ValueError("TPM storage selection requires separate authorization for both tokens")
    return content, (digest_a, digest_b)


def unique_fields(pairs):
    fields = dict(pairs)
    if len(fields) != len(pairs):
        raise ValueError("duplicate fields in the LUKS2 TPM token")
    return fields


def verify_tpm_token(path, expected, pcr_public):
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("exported LUKS2 token does not match the signed storage selection")
    token = json.loads(raw, object_pairs_hook=unique_fields)
    if (
        token["type"] != "systemd-tpm2"
        or token["tpm2-pin"] is not True
        or token["tpm2-pcrs"] != [7, 12, 13]
        or token["tpm2-pcr-bank"] != "sha256"
        or token["tpm2_pubkey_pcrs"] != [11]
        or token["tpm2_pubkey_ref"] != PCR_POLICY_REF
    ):
        raise ValueError("LUKS2 token does not require a PIN and the approved PCR policy")
    for parameter in ("memcost", "iterations", "lanes"):
        value = token[f"tpm2_argon2id_{parameter}"]
        if type(value) is not int or value < 1:
            raise ValueError("the LUKS2 token must harden the PIN with Argon2id")
    token_public = base64.b64decode(token["tpm2_pubkey"], validate=True)
    if run("openssl", "pkey", "-pubin", "-outform", "DER",
           input=token_public, capture_output=True).stdout != pcr_public:
        raise ValueError("the enrolled PCR authority does not match the PCR signing key")


def guest_selection(args, work):
    guest = args.guest_boot
    certificate = args.guest_release_certificate
    if guest is None:
        return (), None
    guest_boot_bundle.require_authority(certificate, None, None,
                                        guest_boot_bundle.public_key(args.boot_certificate),
                                        guest_boot_bundle.public_key(args.runtime_certificate))
    directory = work / "guest"
    directory.mkdir()
    size, parts = read_layout(guest, VERITY_PARTITIONS)
    root = verify_verity(guest, size, parts, args.boot_certificate, directory)
    tree = directory / "tree"
    run("fsck.erofs", f"--extract={tree}", "--preserve-perms", directory / "root")
    if {entry.name for entry in tree.iterdir()} != set(guest_boot_bundle.BUNDLE_FILES):
        raise ValueError("unexpected Guest boot disk contents")
    _, release = guest_boot_bundle.verify(tree, certificate)
    digests = release["files"] | {name: guest_boot_bundle.sha256(tree / name) for name in ("release.json", "release.p7s")}
    checksums = "".join(f"{digests[name]}  {name}\n" for name in guest_boot_bundle.BUNDLE_FILES)
    selection = (f"FVCA-GUEST-LAUNCH-1\nbundle={root}\ncore={release['core_root']}\n"
                 f"runtime={release['runtime_root']}\n{checksums}").encode("ascii")
    files = tuple(zip(GUEST_LAUNCH_FILES, (selection, (directory / "root.p7s").read_bytes()), strict=True))
    return files, root


BACKUP_FILES = ("vm-backup-policy", "vm-backup-ca.pem")
BACKUP_JOB_FILE = "vm-backup-job"
RESTORE_FILE = "vm-restore-authorization"
RETENTION_FILE = "vm-retention-policy"


def backup_selection(args):
    if args.backup_policy is None:
        return ()
    policy = args.backup_policy.read_bytes()
    ca = args.backup_ca.read_bytes()
    backup_destination.parse(policy, ca)
    return tuple(zip(BACKUP_FILES, (policy, ca), strict=True))


def backup_job_selection(path, backup):
    if path is None:
        return ()
    policy = path.read_bytes()
    number = r"([1-9][0-9]{0,7})"
    selected = re.fullmatch(
        rf"FVCA-BACKUP-JOB-1\nrepository=([0-9a-f]{{64}})\ninterval_seconds={number}\nretry_seconds={number}\n"
        rf"max_data_loss_seconds={number}\nmax_quiesce_seconds={number}\nrestore_objective_seconds={number}\n",
        policy.decode("ascii"),
    )
    if selected is None or len(policy) > 2048 or backup[0][1].splitlines()[-1] != f"repository={selected[1]}".encode("ascii"):
        raise ValueError("invalid scheduled backup job or repository scope")
    interval, retry, max_loss, quiesce, restore = map(int, selected.groups()[1:])
    if not (5 <= retry <= 3600 and retry <= interval <= max_loss <= 31_536_000
            and 1 <= quiesce <= 20 and 1 <= restore <= 31_536_000):
        raise ValueError("invalid scheduled backup interval or objectives")
    return ((BACKUP_JOB_FILE, policy),)


def restore_selection(path, backup):
    if path is None:
        return ()
    authorization = path.read_bytes()
    uuid = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    selected = re.fullmatch(
        rf"FVCA-S3-RESTORE-1\nidentity=source-fenced\ncapture={uuid}\nrestore={uuid}\n"
        r"repository=([0-9a-f]{64})\nsnapshot=[0-9a-f]{64}\nmanifest_sha256=[0-9a-f]{64}\n"
        r"disk_sha256=[0-9a-f]{64}\ndisk_bytes=([1-9][0-9]{0,19})\ntotal_bytes=([1-9][0-9]{0,19})\n",
        authorization.decode("ascii"),
    )
    if selected is None or backup[0][1].splitlines()[-1] != f"repository={selected[1]}".encode("ascii"):
        raise ValueError("invalid S3 restore authorization or repository ID")
    disk, total = int(selected[2]), int(selected[3])
    if disk % 512 or not disk < total < 2**64:
        raise ValueError("invalid S3 restore size authorization")
    return ((RESTORE_FILE, authorization),)


def retention_selection(path, backup):
    if path is None:
        return ()
    policy = path.read_bytes()
    number = r"([1-9][0-9]{0,19})"
    uuid = r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"
    selected = re.fullmatch(
        rf"FVCA-LOCAL-RETENTION-1\nrepository=([0-9a-f]{{64}})\nkeep_min={number}\nkeep_max={number}\n"
        rf"max_age_seconds={number}\nmin_data_bytes={number}\nmin_metadata_bytes={number}\n((?:protect={uuid}\n)*)",
        policy.decode("ascii"),
    )
    if selected is None or len(policy) > 8192 or backup[0][1].splitlines()[-1] != f"repository={selected[1]}".encode("ascii"):
        raise ValueError("invalid local retention policy or repository scope")
    keep_min, keep_max, *limits = map(int, selected.groups()[1:6])
    protected = selected[7].splitlines()
    if not 1 <= keep_min <= keep_max <= 4096 or max(limits) >= 2**64 or len(protected) != len(set(protected)):
        raise ValueError("invalid local retention budgets or protected capture IDs")
    return ((RETENTION_FILE, policy),)


TRIAL_FILE = "hypervisor-trial"
TRIAL_CANDIDATE_FILE = "hypervisor-trial-candidate"
TRIAL_SUPPORT = "hypervisor-trial-support-v2"


def trial_selection(path, ids, guest, *, candidate):
    if path is None:
        return ()
    uuid = r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"
    policy = path.read_bytes()
    head = "FVCA-HYPERVISOR-TRIAL-CANDIDATE-1" if candidate else "FVCA-HYPERVISOR-TRIAL-2"
    tail = "" if candidate else (
        r"candidate_esp_sha256=[0-9a-f]{64}\ncandidate_esp_bytes=([1-9][0-9]{0,9})\n"
        r"candidate_core=[0-9a-f]{64}\ncandidate_runtime=[0-9a-f]{64}\nguest_bundle=([0-9a-f]{64})\n"
    )
    selected = re.fullmatch(rf"{head}\ntransaction={uuid}\n"
                            rf"stable=([0-9a-f]{{4}}),({uuid})\ncandidate=([0-9a-f]{{4}}),({uuid})\n{tail}",
                            policy.decode("ascii"))
    if selected is None or ids is None:
        raise ValueError("invalid Hypervisor boot trial authorization")
    stable_id, stable, candidate_id, target, *approval = selected.groups()
    if (target if candidate else stable) != ids["esp"] or stable == target or stable_id == candidate_id:
        raise ValueError("trial requires distinct boot entries and the ESP of the slot being composed")
    if candidate:
        return ((TRIAL_CANDIDATE_FILE, policy),)
    size, expected_guest = approval
    size = int(size)
    if not 4096 <= size <= 4 * 1024**3 or size % 4096 or guest != expected_guest:
        raise ValueError("trial requires a bounded candidate ESP and the selected Guest bundle")
    return ((TRIAL_FILE, policy),)


def assemble(args, work):
    storage, digests = storage_selection(args.storage) if args.storage is not None else (None, (None, None))
    tpm = digests[0] is not None
    token_paths = (args.tpm_token_a, args.tpm_token_b)
    if tpm != (args.pcr_key is not None) or any(tpm != (path is not None) for path in token_paths):
        raise ValueError("TPM storage requires a separate PCR signing key and both exported LUKS2 tokens")
    pcr_options = []
    if tpm:
        boot_public = run("openssl", "pkey", "-in", args.boot_key, "-pubout", "-outform", "DER",
                          capture_output=True).stdout
        pcr_public = run("openssl", "pkey", "-in", args.pcr_key, "-pubout", "-outform", "DER",
                         capture_output=True).stdout
        if pcr_public == boot_public:
            raise ValueError("PCR policy and Secure Boot must use different signing keys")
        for path, digest in zip(token_paths, digests, strict=True):
            verify_tpm_token(path, digest, pcr_public)
        pcr_options = [
            f"--pcr-private-key={args.pcr_key}",
            "--pcr-banks=sha256", "--phases=enter-initrd", f"--policyref={PCR_POLICY_REF}",
        ]
    prepared, core_hash, offset, cmdline, uname = prepare_core(args, work)
    runtime_work = work / "runtime"
    runtime_work.mkdir()
    runtime_hash = verify_runtime(args.runtime, args.runtime_certificate, prepared, runtime_work, vm_runtime)
    forbidden = tuple(f"usr/lib/fvca/{name}" for name in (
        "hypervisor.composition", "vm-runtime.p7s", "host-storage",
        *WORKLOAD_TRUST_FILES, *DIRECT_BOOT_FILES, *GUEST_LAUNCH_FILES, *BACKUP_FILES, BACKUP_JOB_FILE,
        RESTORE_FILE, RETENTION_FILE, hypervisor_gpt.MANIFEST, hypervisor_gpt.ROOT_SIGNATURE, TRIAL_FILE,
        TRIAL_CANDIDATE_FILE,
    ))
    required = ACTIVATION_FILES
    if args.gpt_slot:
        required += (f"usr/lib/fvca/{hypervisor_gpt.SUPPORT}",)
    if args.boot_trial is not None or args.boot_trial_candidate is not None:
        required += (f"usr/lib/fvca/{TRIAL_SUPPORT}", "usr/lib/fvca/set-boot-next")
    if args.boot_trial_candidate is not None:
        recorder = runtime_work / "tree" / vm_runtime.TRIAL_HEALTH
        if recorder.is_symlink() or not recorder.is_file() or recorder.stat().st_mode & 0o111 == 0:
            raise ValueError("the candidate VM runtime lacks its trial health recorder")
    verify_initrd(args.initrd, uname, required, forbidden, "Hypervisor")
    extra = (("host-storage", storage),) if storage is not None else ()
    ids = None
    if args.gpt_slot:
        ids, slot_files = hypervisor_gpt.approval(args.gpt_slot, prepared)
        extra += slot_files
    backup = backup_selection(args)
    guest, guest_hash = guest_selection(args, work)
    composition = composition_archive(
        work, args.boot_key, args.boot_certificate, core_hash, runtime_hash, "hypervisor", "vm-runtime",
        extra=(*extra, *guest, *backup, *backup_job_selection(args.backup_job, backup),
               *restore_selection(args.restore_authorization, backup),
               *retention_selection(args.retention_policy, backup),
               *trial_selection(args.boot_trial, ids, guest_hash, candidate=False),
               *trial_selection(args.boot_trial_candidate, ids, guest_hash, candidate=True)),
    )
    cmdline = " ".join((cmdline, *ROLE_BOOT_OPTIONS))
    if ids is None:
        disk, _ = write_disk(args, work, offset, cmdline, uname, composition, uki_options=pcr_options)
    else:
        disk = hypervisor_gpt.pack(args, work, ids, cmdline, uname, composition, pcr_options)
    args.output.hardlink_to(disk)
    print(f"FVCA Hypervisor development disk binds core {core_hash} to VM runtime {runtime_hash}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("core", "runtime", "initrd", "boot-certificate", "boot-key", "runtime-certificate", "output"):
        parser.add_argument(f"--{name}", type=lambda value: Path(value).absolute(), required=True)
    parser.add_argument("--storage", type=Path, help="host storage selection to embed in the signed UKI")
    parser.add_argument("--guest-boot", type=Path, help="verified Guest boot bundle disk to authorize")
    parser.add_argument("--guest-release-certificate", type=Path, help="trusted Guest release signer")
    parser.add_argument("--gpt-slot", type=UUID, help="assign one unique UUID to a self-contained Hypervisor GPT slot image")
    parser.add_argument("--gpt-sector-size", type=int, choices=(512, 4096), help="GPT slot logical sector size (default 4096)")
    trial = parser.add_mutually_exclusive_group()
    trial.add_argument("--boot-trial", type=Path, help="authorize a specific one-shot UEFI trial from the stable GPT slot")
    trial.add_argument("--boot-trial-candidate", type=Path, help="validate readiness during the authorized GPT trial")
    parser.add_argument("--backup-policy", type=Path, help="S3 destination and repository ID to authorize in this UKI")
    parser.add_argument("--backup-ca", type=Path, help="PEM trust bundle for the selected S3 endpoint")
    parser.add_argument("--backup-job", type=Path, help="authorize the periodic live Service Guest backup job")
    parser.add_argument("--restore-authorization", type=Path, help="exact S3 recovery set to authorize in a recovery UKI")
    parser.add_argument("--retention-policy", type=Path, help="authorize local capture expiry against the selected repository")
    parser.add_argument("--pcr-key", type=Path, help="separate RSA private key for the initrd PCR policy")
    for member in ("a", "b"):
        parser.add_argument(f"--tpm-token-{member}", type=Path, help=f"exported LUKS2 token for member {member}")
    args = parser.parse_args()
    if (args.guest_boot is None) != (args.guest_release_certificate is None) or (
        args.guest_boot is not None and args.storage is None
    ):
        parser.error("Guest boot requires its signed bundle disk, release certificate, and Host storage")
    if args.output.exists():
        parser.error("output disk already exists")
    if args.gpt_slot is not None and args.guest_boot is None:
        parser.error("a GPT slot requires its authorized Guest boot bundle")
    if args.gpt_sector_size is not None and args.gpt_slot is None:
        parser.error("sector size is only configurable for a GPT slot image")
    if (args.boot_trial is not None or args.boot_trial_candidate is not None) and args.gpt_slot is None:
        parser.error("a boot trial requires a GPT slot")
    if args.boot_trial_candidate is not None and args.restore_authorization is not None:
        parser.error("a boot trial candidate requires ordinary Guest startup")
    if (args.backup_policy is None) != (args.backup_ca is None) or (
        args.backup_policy is not None and args.guest_boot is None
    ):
        parser.error("VM backup requires an authorized Guest, destination policy, and endpoint CA")
    if args.restore_authorization is not None and args.backup_policy is None:
        parser.error("S3 recovery requires an authorized repository and Guest")
    if args.backup_job is not None and (
        args.backup_policy is None or args.retention_policy is None or args.restore_authorization is not None
    ):
        parser.error("the scheduled backup job requires an ordinary Hypervisor, authorized repository and local retention")
    if args.retention_policy is not None and args.backup_policy is None:
        parser.error("local capture expiry requires the authorized backup repository")
    try:
        with tempfile.TemporaryDirectory(prefix=".fvca-hypervisor-", dir=args.output.parent) as directory:
            assemble(args, Path(directory))
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"FVCA Hypervisor composition failed: {error}\n")


if __name__ == "__main__":
    main()
