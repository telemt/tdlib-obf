# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT

import pathlib
import unittest

from import_traffic_dumps import derive_capture_plan


class ImportTrafficDumpsProfileIdIntegrationTest(unittest.TestCase):
    def test_real_capture_names_produce_unique_profile_ids(self) -> None:
        real_capture_names = [
            "Android_10,_Google_Chrome_146,_auto_Android_10,_auto_Google_Chro.pcap",
            "Android_16,_IronFox_149_0,_auto_Android_10,_auto_Firefox_149_0.pcap",
            "iOS 26.5, Safari 26.5, auto iOS 18.7, auto Safari 26.5.pcap",
            "Windows_10_0,_Edge_146_0_0_0,_auto_Windows_10_0,_auto_Edge_146_0.pcap",
            "Windows_11_23h2,_Chromium_142,_auto_Windows_10_0,_auto_Chromium.pcap",
        ]

        profile_ids = {
            derive_capture_plan(pathlib.Path(capture_name)).profile_id
            for capture_name in real_capture_names
        }

        self.assertEqual(len(real_capture_names), len(profile_ids))


if __name__ == "__main__":
    unittest.main()