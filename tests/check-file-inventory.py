#!/usr/bin/env python3
"""Check file identity and fail-closed archive handling in role inventories."""

import hashlib
from io import BytesIO
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from file_inventory import newc_inventory, tree_inventory


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
        self.archive = subprocess.check_output(
            ["cpio", "--quiet", "-o", "-0", "--format=newc", "--reproducible", "--owner=0:0"],
            cwd=self.root, input=b".\0linked\0origin\0symlink\0",
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


if __name__ == "__main__":
    unittest.main()
