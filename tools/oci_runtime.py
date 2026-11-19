"""Keep the reviewed Service Guest OCI payload and check that it is additive."""

from pathlib import Path
import re

import runtime_tree


IMAGE_ID = "oci-runtime"
BASE_INPUT = "service-guest-runtime-base"
BASE_BINDING = Path("usr/share/fvca/oci-runtime-base.roothash")
EXTENSION_RELEASE = Path("usr/lib/extension-release.d/extension-release.oci-runtime")
REQUIRED_FILES = {
    *(Path("usr/bin") / name for name in ("podman", "crun", "conmon", "restic")),
    *(Path("usr/libexec/podman") / name for name in ("quadlet", "netavark", "aardvark-dns")),
    Path("usr/libexec/catatonit/catatonit"),
    Path("usr/lib64/libpodman_sequoia.so.0"),
    BASE_BINDING,
    EXTENSION_RELEASE,
}
LIBRARIES = re.compile(r"lib(?:assuan|glib-2\.0|gpg-error|gpgme|podman_sequoia|subid)\.so(?:\.[0-9]+)*")


def allowed(path):
    return (
        path in REQUIRED_FILES
        or path.is_relative_to("usr/share/licenses")
        or path.parent == Path("usr/lib64") and LIBRARIES.fullmatch(path.name) is not None
    )


def inspect_tree(root, base, *, prune):
    if (base / "usr/lib/fvca/role").read_bytes() != b"service-guest\n":
        raise ValueError("OCI runtime requires a Service Guest core")
    runtime_tree.inspect_tree(root, base, allowed=allowed, required=REQUIRED_FILES, prune=prune)
