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


class SynMetadataParserMalformedPackets(unittest.TestCase):
    def test_rejects_out_of_range_ttl(self) -> None:
        with self.assertRaisesRegex(ValueError, "ttl must be in"):
            extractor.parse_syn_transport_traits_row(
                {
                    "ip_ttl": "999",
                    "ipv6_hlim": "",
                    "tcp_mss": "1460",
                    "tcp_wscale": "8",
                    "tcp_options_kind": "2,4,8,1,3",
                    "ip_id": "1",
                }
            )

    def test_rejects_negative_mss(self) -> None:
        with self.assertRaisesRegex(ValueError, "mss must be positive"):
            extractor.parse_syn_transport_traits_row(
                {
                    "ip_ttl": "64",
                    "ipv6_hlim": "",
                    "tcp_mss": "-1",
                    "tcp_wscale": "8",
                    "tcp_options_kind": "2,4,8,1,3",
                    "ip_id": "1",
                }
            )

    def test_rejects_invalid_option_kind_token(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid tcp option kind"):
            extractor.classify_syn_option_order("2,4,abc")


if __name__ == "__main__":
    unittest.main()
