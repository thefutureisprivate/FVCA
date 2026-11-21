#!/usr/bin/env python3
"""Check file identity and fail-closed archive handling in role inventories."""

from compression import zstd
import hashlib
from io import BytesIO
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from file_inventory import composed_initramfs, newc_inventory, tree_inventory


class InventoryTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.content = b"FVCA byte inventory\n"
        original = self.root / "origin"
        original.write_bytes(self.content)
        original.chmod(0o640)
        (self.root / "linked").hardlink_to(original)
        (self.root / "symlink").symlink_to("/missing/target")
        self.archive = self.archive_for(b".\0linked\0origin\0symlink\0")

    def archive_for(self, paths):
        return subprocess.check_output(
            ["cpio", "--quiet", "-o", "-0", "--format=newc", "--reproducible", "--owner=0:0"],
            cwd=self.root, input=paths,
        )

    def test_hardlink_and_symlink_records(self):
        for entries in (tree_inventory(self.root), newc_inventory(BytesIO(self.archive))):
            with self.subTest(source=entries[0]):
                by_path = {entry["path"]: entry for entry in entries}
                self.assertEqual(set(by_path), {"/", "/linked", "/origin", "/symlink"})
                for path in ("/linked", "/origin"):
                    entry = by_path[path]
                    self.assertEqual(entry["mode"], "0640")
                    self.assertEqual(entry["size"], len(self.content))
                    self.assertEqual(entry["sha256"], hashlib.sha256(self.content).hexdigest())
                self.assertEqual(by_path["/origin"]["hardlink"], "/linked")
                self.assertEqual(by_path["/symlink"]["target"], "/missing/target")

    def test_rejects_truncated_or_extra_content(self):
        marker = self.archive.index(b"TRAILER!!!\0")
        for bad in (self.archive[:marker], self.archive + b"trailing"):
            with self.subTest(size=len(bad)), self.assertRaises(ValueError):
                newc_inventory(BytesIO(bad))

    def test_rejects_ambiguous_paths(self):
        for replacement in (b"../bad\0", b"origin\0"):
            with self.subTest(name=replacement), self.assertRaises(ValueError):
                newc_inventory(BytesIO(self.archive.replace(b"linked\0", replacement, 1)))

    def test_composed_initramfs_keeps_configuration_separate(self):
        policy = self.root / "usr/lib/fvca"
        policy.mkdir(parents=True)
        (policy / "base").write_bytes(b"base")
        (policy / "configuration").write_bytes(b"configuration")
        base = zstd.compress(self.archive_for(b".\0usr\0usr/lib\0usr/lib/fvca\0usr/lib/fvca/base\0"))
        aligned = base + b"\0" * (-len(base) % 4)
        output = self.root / "initrd"
        captured = {"/usr/lib/fvca/configuration": None}
        output.write_bytes(aligned + self.archive_for(b"usr/lib/fvca/configuration\0"))
        result = composed_initramfs(output, self.root, captured)
        self.assertEqual(captured["/usr/lib/fvca/configuration"], b"configuration")
        self.assertEqual([entry["path"] for entry in result["configuration_files"]], list(captured))
        output.write_bytes(aligned + self.archive_for(b"usr/lib/fvca/base\0"))
        with self.assertRaisesRegex(ValueError, "replaces a base initramfs file"):
            composed_initramfs(output, self.root, {})


if __name__ == "__main__":
    unittest.main()
