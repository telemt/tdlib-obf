#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs

from __future__ import annotations

import pathlib
import random
import sys
import unittest

THIS_DIR = pathlib.Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

import extract_tcp_transport_signatures as extractor  # noqa: E402


class TCPTransportExtractionFuzzStress(unittest.TestCase):
    def test_light_fuzz_record_lengths_never_crashes(self) -> None:
        rng = random.Random(20260425)
        for _ in range(10000):
            kind = rng.randrange(6)
            if kind == 0:
                sample = {"record_lengths": [rng.randrange(1, 65536)]}
            elif kind == 1:
                sample = {"record_lengths": [rng.randrange(-1000, 70000)]}
            elif kind == 2:
                sample = {"record_lengths": ["x", 123]}
            elif kind == 3:
                sample = {"record_length": rng.randrange(-1000, 70000)}
            elif kind == 4:
                sample = {}
            else:
                sample = {"record_lengths": []}

            try:
                result = extractor._record_lengths_from_sample(sample)
                self.assertIsInstance(result, list)
                for value in result:
                    self.assertIsInstance(value, int)
                    self.assertGreater(value, 0)
                    self.assertLessEqual(value, 65535)
            except ValueError:
                pass

    def test_stress_segmentation_rate_is_deterministic(self) -> None:
        values = [100, 120, 300, 999, 2499, 2500, 3000] * 2048
        expected = extractor._compute_first_flight_segmentation_rate(values)
        for _ in range(1000):
            self.assertEqual(expected, extractor._compute_first_flight_segmentation_rate(values))


if __name__ == "__main__":
    unittest.main()
