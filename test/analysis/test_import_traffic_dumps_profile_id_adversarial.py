# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT

import pathlib
import unittest
from unittest import mock

from import_traffic_dumps import derive_capture_plan


class ImportTrafficDumpsProfileIdAdversarialTest(unittest.TestCase):
    def test_profile_id_generation_never_calls_sha1(self) -> None:
        capture = pathlib.Path(
            "Windows_10_0,_Firefox_149_0,_auto_Windows_10_0,_auto_Firefox_149.pcap"
        )

        with mock.patch("import_traffic_dumps.hashlib.sha1", side_effect=AssertionError("sha1 must not be used")):
            plan = derive_capture_plan(capture)

        self.assertIn("firefox", plan.profile_id)

    def test_disambiguation_suffix_changes_profile_id_suffix(self) -> None:
        original = derive_capture_plan(
            pathlib.Path("iOS 26.4, Safari 26.4, auto iOS 18.7, auto Safari 26.4.pcap")
        )
        disambiguated = derive_capture_plan(
            pathlib.Path("iOS 26.4, Safari 26.4, auto iOS 18.7, auto Safari 26.4__deadbeef.pcap")
        )

        self.assertNotEqual(original.profile_id, disambiguated.profile_id)
        self.assertNotEqual(
            original.profile_id.rsplit("_", 1)[-1],
            disambiguated.profile_id.rsplit("_", 1)[-1],
        )


if __name__ == "__main__":
    unittest.main()