# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT

import hashlib
import pathlib
import unittest

from import_traffic_dumps import derive_capture_plan


class ImportTrafficDumpsProfileIdContractTest(unittest.TestCase):
    def test_profile_suffix_matches_sha256_contract(self) -> None:
        capture = pathlib.Path(
            "Android_10,_Google_Chrome_146,_auto_Android_10,_auto_Google_Chro.pcap"
        )

        plan = derive_capture_plan(capture)

        expected_suffix = hashlib.sha256(capture.stem.encode("utf-8")).hexdigest()[:12]
        self.assertTrue(plan.profile_id.endswith(f"_{expected_suffix}"))

    def test_profile_suffix_length_is_twelve_hex_chars(self) -> None:
        capture = pathlib.Path("iOS 26.5, Safari 26.5, auto iOS 18.7, auto Safari 26.5.pcap")

        plan = derive_capture_plan(capture)

        suffix = plan.profile_id.rsplit("_", 1)[-1]
        self.assertRegex(suffix, r"^[0-9a-f]{12}$")


if __name__ == "__main__":
    unittest.main()