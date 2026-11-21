"""Off-node source admission and isolated workload derivation."""

import base64
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

import workload_oci as oci
import workload_permit as permit


TOOL_ROOT = Path(__file__).resolve().parent
OUTPUTS = ("root.erofs", "verity.hash", "roothash", "launch.json", "derivation.json")
SOURCE_EVIDENCE = "source-evidence.json"


def source_arguments(parser):
    for name in ("policy", "source-index", "layout", "output"):
        parser.add_argument(f"--{name}", type=lambda value: Path(value).absolute(), required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--cosign", type=Path)
    source.add_argument("--unsigned-permit", type=Path, help="directory containing the independently issued permit")
    parser.add_argument("--worker-image", required=True, help="immutable local image ID of the reviewed workload converter")


def check_publisher(cosign, policy):
    environment = {
        name: value for name, value in os.environ.items()
        if not name.startswith(("COSIGN_", "SIGSTORE_", "TUF_"))
    }
    version = subprocess.check_output([cosign, "version", "--json"], env=environment, timeout=15)
    if oci.parse_json(version)["gitVersion"] != "v3.1.4":
        raise ValueError("publisher verification requires Cosign v3.1.4")
    reference = f"{policy['repository']}@{policy['index']}"
    proof = subprocess.check_output([
        cosign, "verify", "--certificate-identity", policy["certificate_identity"],
        "--certificate-oidc-issuer", policy["certificate_issuer"], "--check-claims=true",
        "--insecure-ignore-tlog=false", "--output", "json", "--", reference,
    ], env=environment, timeout=120)
    claims_ref = reference.replace("docker.io/", "index.docker.io/", 1) if reference.startswith("docker.io/") else reference
    if len(proof) > oci.METADATA_LIMIT or not any(
        item["critical"]["type"] == "https://sigstore.dev/cosign/sign/v1"
        and item["critical"]["image"]["docker-manifest-digest"] == policy["index"]
        and item["critical"]["identity"]["docker-reference"] == claims_ref
        for item in oci.parse_json(proof)
    ):
        raise ValueError("publisher verification returned no matching OCI signature claim")
    return proof


def publish(staged, output):
    # Rename within the target filesystem and keep any concurrently created output.
    subprocess.run(["mv", "--no-clobber", "--no-target-directory", "--", staged, output], check=True)
    if staged.exists():
        raise FileExistsError(f"{output} already exists")


def mount(path, target, options):
    if any(character in str(path) for character in (":", ",", "\n")):
        raise ValueError("worker input and output paths must be plain local paths")
    return f"{path}:{target}:{options}"


def derive(args, destination):
    engine = ["podman", "--remote=false"]
    oci.digest_hex(args.worker_image)
    if subprocess.check_output([*engine, "info", "--format", "{{.Host.Security.Rootless}}"], text=True).strip() != "true":
        raise ValueError("workload conversion requires rootless Podman")
    image = subprocess.check_output(
        [*engine, "image", "inspect", "--format", "{{.Id}}", args.worker_image], text=True,
    ).strip()
    image = f"sha256:{image}" if ":" not in image else image
    if image != args.worker_image:
        raise ValueError("the local workload converter does not match the approved image ID")

    destination.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(prefix=".workload-input-", dir=destination.parent) as directory:
        staged = Path(directory)
        policy_raw = oci.read_bytes(args.policy)
        policy = oci.parse_json(policy_raw)
        if args.unsigned_permit is None:
            oci.validate_policy(policy)
        else:
            oci.validate_exception_policy(policy)
        raw_launch = oci.snapshot_source(policy, policy_raw, args.source_index, args.layout, staged)
        launch = oci.json_bytes(oci.launch_metadata(policy, raw_launch))
        request, authority_key = None, None
        if args.unsigned_permit is None:
            proof = {"provenance": permit.PUBLISHER, "policy": permit.portable(policy_raw),
                     "proof": oci.parse_json(check_publisher(args.cosign.absolute(), policy))}
        else:
            proof, request, authority_key = permit.verify(args.unsigned_permit, policy, policy_raw, launch, staged)
            for name in ("permit.json", "permit.p7s", "authority.crt"):
                (staged / name).unlink()
        for name in ("workload_worker.py", "workload_oci.py"):
            shutil.copyfile(TOOL_ROOT / name, staged / name)
        subprocess.run([
            *engine, "run", "--rm", "--pull=never", "--network=none", "--read-only",
            "--pids-limit=64", "--memory=1g", "--cpus=2", "--security-opt=no-new-privileges",
            "--cap-drop=all", "--cap-add=CHOWN", "--cap-add=DAC_OVERRIDE",
            "--cap-add=FOWNER", "--cap-add=FSETID", "--cap-add=SETFCAP",
            "--tmpfs", "/work:rw,nosuid,nodev,noexec,size=640m,mode=0700",
            "--volume", mount(staged, "/input", "ro,Z"),
            "--volume", mount(destination, "/output", "rw,Z"),
            image, "/usr/bin/python3", "/input/workload_worker.py", "/input", "/output", "/work",
        ], check=True, timeout=240)

        if sorted(path.name for path in destination.iterdir()) != sorted(OUTPUTS):
            raise ValueError("workload worker produced unexpected outputs")
        evidence_file = destination / "derivation.json"
        evidence = oci.parse_json(oci.read_bytes(evidence_file))
        if (evidence["source"] != oci.source_record(policy) or evidence["manifest"]["digest"] != policy["manifest"]
                or evidence["source_policy"] != oci.sha256(policy_raw)
                or oci.read_bytes(destination / "launch.json") != launch or evidence["launch"] != oci.sha256(launch)):
            raise ValueError("workload worker recorded a different source selection")
        evidence["worker_image"] = image
        evidence["provenance"] = proof["provenance"]
        if request is not None:
            if int(time.time()) >= request["expires"]:
                raise ValueError("unsigned workload permit expired during derivation")
            evidence["permit"] = oci.sha256(base64.b64decode(proof["permit"], validate=True))
        evidence_file.write_bytes(oci.json_bytes(evidence))
        receipt = oci.json_bytes(proof)
        if len(receipt) > oci.METADATA_LIMIT:
            raise ValueError("source evidence exceeds the authorization record size limit")
        (destination / SOURCE_EVIDENCE).write_bytes(receipt)
    return evidence, request, authority_key
