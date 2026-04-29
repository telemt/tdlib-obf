# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT

import pathlib
import unittest

from import_traffic_dumps import derive_capture_plan


class ImportTrafficDumpsProfileIdStressTest(unittest.TestCase):
    def test_profile_id_collision_rate_stays_zero_for_large_batch(self) -> None:
        profile_ids: set[str] = set()

        for index in range(10000):
            capture_name = (
                f"Android_16,_Google_Chrome_146_0_7680_{index},"
                f"_auto_Android_10,_auto_Google_Chrome_146.pcap"
            )
            profile_ids.add(derive_capture_plan(pathlib.Path(capture_name)).profile_id)

        self.assertEqual(10000, len(profile_ids))


if __name__ == "__main__":
    unittest.main()