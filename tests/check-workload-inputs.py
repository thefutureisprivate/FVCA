#!/usr/bin/env python3
"""Check the conversion boundary against unsafe OCI metadata."""

from pathlib import Path
import sys
import tarfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from workload_oci import parse_json
from workload_network import parse as parse_uplink
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

    def test_workload_uplink_requires_two_bounded_canonical_rates(self):
        profile = ("FVCA-GUEST-WORKLOAD-NETWORK-2\npci=0000:00:06.0\nmac=52:54:00:10:20:30\n"
                   "address=192.168.44.15/24\ngateway=none\nmtu=1400\ndns=none\n"
                   "receive_bytes_per_second=65536\nsend_bytes_per_second=125000000\n")
        parse_uplink(profile)
        for changed in (profile.replace("65536", "65535"), profile.replace("125000000", "125000001"),
                        profile.replace("65536", "065536"), profile.replace("send_bytes_per_second=125000000\n", ""),
                        profile + "receive_bytes_per_second=65536\n", profile.replace("NETWORK-2", "NETWORK-1")):
            with self.subTest(profile=changed), self.assertRaises(ValueError):
                parse_uplink(changed)


if __name__ == "__main__":
    unittest.main()
