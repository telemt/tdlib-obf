#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT

from __future__ import annotations

import pathlib
import random
import sys
import unittest

THIS_DIR = pathlib.Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

import extract_client_hello_fixtures as extractor  # noqa: E402


class FuzzSynMetadataExtractor(unittest.TestCase):
    def test_light_fuzz_never_crashes(self) -> None:
        rng = random.Random(20260426)
        for _ in range(10000):
            row = {
                "ip_ttl": str(rng.randrange(-100, 400)) if rng.randrange(2) else "",
                "ipv6_hlim": str(rng.randrange(-100, 400)) if rng.randrange(2) else "",
                "tcp_mss": str(rng.randrange(-1000, 10000)) if rng.randrange(2) else "",
                "tcp_wscale": str(rng.randrange(-20, 40)) if rng.randrange(2) else "",
                "tcp_options_kind": ",".join(str(rng.randrange(-5, 400)) for _ in range(rng.randrange(0, 8))),
                "ip_id": str(rng.randrange(-10, 70000)) if rng.randrange(2) else "",
            }
            try:
                traits = extractor.parse_syn_transport_traits_row(row)
                self.assertIn("available", traits)
            except ValueError:
                pass


if __name__ == "__main__":
    unittest.main()
