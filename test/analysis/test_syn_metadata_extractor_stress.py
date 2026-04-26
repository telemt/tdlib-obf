#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT

from __future__ import annotations

import pathlib
import sys
import unittest

THIS_DIR = pathlib.Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

import extract_client_hello_fixtures as extractor  # noqa: E402


class SynMetadataExtractorStress(unittest.TestCase):
    def test_stress_deterministic_bucketing(self) -> None:
        row = {
            "ip_ttl": "64",
            "ipv6_hlim": "",
            "tcp_mss": "1460",
            "tcp_wscale": "8",
            "tcp_options_kind": "2,4,8,1,3",
            "ip_id": "500",
        }
        expected = extractor.parse_syn_transport_traits_row(row)
        for _ in range(20000):
            self.assertEqual(expected, extractor.parse_syn_transport_traits_row(row))


if __name__ == "__main__":
    unittest.main()
