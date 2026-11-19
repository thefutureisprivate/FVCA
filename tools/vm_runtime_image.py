"""Verify a signed VM runtime candidate against its prepared FVCA core."""

import subprocess

from image_verity import VERITY_PARTITIONS, read_layout, verify_verity
from vm_runtime import BASE_BINDING, EXTENSION_RELEASE, inspect_tree


def verify(image, certificate, prepared, work):
    sector_size, partitions = read_layout(image, VERITY_PARTITIONS)
    root_hash = verify_verity(image, sector_size, partitions, certificate, work)
    tree = work / "tree"
    subprocess.run(["fsck.erofs", f"--extract={tree}", "--preserve-perms", work / "root"], check=True)
    if sorted(path.name for path in tree.iterdir()) != ["usr"]:
        raise ValueError("expected a runtime image containing only /usr")
    inspect_tree(tree, prepared / "root", prune=False)

    binding = (prepared / "roothash").read_bytes()
    if (tree / BASE_BINDING).read_bytes() != binding:
        raise ValueError("VM runtime was built against a different base root")
    release = (tree / EXTENSION_RELEASE).read_text(encoding="ascii").splitlines()
    if sorted(release) != sorted((
        "ARCHITECTURE=x86-64", "ID=fedora", "VERSION_ID=45", "SYSEXT_ID=vm-runtime", "SYSEXT_SCOPE=initrd",
    )):
        raise ValueError("unexpected VM runtime extension identity")
    return root_hash
