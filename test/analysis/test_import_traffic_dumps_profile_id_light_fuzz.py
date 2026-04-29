# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT

import pathlib
import string
import unittest

from import_traffic_dumps import derive_capture_plan


class ImportTrafficDumpsProfileIdLightFuzzTest(unittest.TestCase):
    def test_profile_id_remains_safe_under_noisy_inputs(self) -> None:
        letters = string.ascii_letters + string.digits + " _-.#"

        for index in range(1000):
            # Deterministic non-random fuzz corpus generation to avoid pseudo-random APIs.
            noise = "".join(
                letters[(index * 13 + offset * 17) % len(letters)]
                for offset in range(24)
            ).strip()
            capture_name = (
                f"Android_16,_Google_Chrome_146,_auto_Android_10,_auto_{noise}.pcap"
            )
            plan = derive_capture_plan(pathlib.Path(capture_name))
            self.assertRegex(plan.profile_id, r"^[a-z0-9_]+$")
            self.assertRegex(plan.profile_id.rsplit("_", 1)[-1], r"^[0-9a-f]{12}$")


if __name__ == "__main__":
    unittest.main()
