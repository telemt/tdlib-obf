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


class SynOptionOrderBucketExtraction(unittest.TestCase):
    def test_ttl_bucket_edges(self) -> None:
        self.assertEqual("ttl_0_32", extractor.classify_ttl_bucket(32))
        self.assertEqual("ttl_33_64", extractor.classify_ttl_bucket(64))
        self.assertEqual("ttl_65_96", extractor.classify_ttl_bucket(65))
        self.assertEqual("ttl_97_128", extractor.classify_ttl_bucket(128))
        self.assertEqual("ttl_129_192", extractor.classify_ttl_bucket(192))
        self.assertEqual("ttl_193_255", extractor.classify_ttl_bucket(255))

    def test_syn_option_order_class_normalization(self) -> None:
        self.assertEqual("2-4-8-1-3", extractor.classify_syn_option_order("2,4,8,1,3"))
        self.assertEqual("2-4-8-1-3", extractor.classify_syn_option_order("2,4,8,1,3,3"))
        self.assertEqual("none", extractor.classify_syn_option_order(""))

    def test_mss_and_window_scale_bucket_edges(self) -> None:
        self.assertEqual("mss_537_1200", extractor.classify_mss_bucket(1200))
        self.assertEqual("mss_1201_1460", extractor.classify_mss_bucket(1460))
        self.assertEqual("mss_1461_plus", extractor.classify_mss_bucket(1461))
        self.assertEqual("wscale_0_2", extractor.classify_window_scale_bucket(2))
        self.assertEqual("wscale_3_5", extractor.classify_window_scale_bucket(3))
        self.assertEqual("wscale_6_8", extractor.classify_window_scale_bucket(6))
        self.assertEqual("wscale_9_plus", extractor.classify_window_scale_bucket(9))


if __name__ == "__main__":
    unittest.main()
