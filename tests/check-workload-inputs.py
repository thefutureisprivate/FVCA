#!/usr/bin/env python3
"""Check the conversion boundary against unsafe OCI metadata."""

from pathlib import Path
import sys
import tarfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from workload_oci import parse_json
from workload_worker import check_member


class WorkloadInputTests(unittest.TestCase):
    def test_duplicate_fields(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            parse_json(b'{"digest":"first","digest":"second"}')

    def test_paths(self):
        for name in ("/etc/hosts", "usr/../../etc/hosts"):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "archive path"):
                check_member(tarfile.TarInfo(name))

    def test_link_targets(self):
        member = tarfile.TarInfo("usr/bin/helper")
        member.type = tarfile.SYMTYPE
        member.linkname = "../../outside"   # Stays within the image.
        check_member(member)
        member.linkname = "../../../outside"
        with self.assertRaisesRegex(ValueError, "symlink escapes"):
            check_member(member)
        member.type = tarfile.LNKTYPE
        member.linkname = "/outside"
        with self.assertRaisesRegex(ValueError, "archive path"):
            check_member(member)

    def test_whiteout_and_special_inodes(self):
        whiteout = tarfile.TarInfo("var/cache/.wh..wh..opq")
        check_member(whiteout)
        whiteout.size = 1
        with self.assertRaisesRegex(ValueError, "whiteout"):
            check_member(whiteout)
        device = tarfile.TarInfo("dev/unapproved")
        device.type = tarfile.CHRTYPE
        with self.assertRaisesRegex(ValueError, "object type"):
            check_member(device)

    def test_security_attributes(self):
        member = tarfile.TarInfo("usr/bin/application")
        member.pax_headers = {"SCHILY.xattr.security.selinux": "system_u:object_r:bin_t:s0"}
        with self.assertRaisesRegex(ValueError, "extended metadata"):
            check_member(member)
        member.pax_headers = {"SCHILY.xattr.trusted.overlay.opaque": "y"}
        with self.assertRaisesRegex(ValueError, "extended metadata"):
            check_member(member)


if __name__ == "__main__":
    unittest.main()
