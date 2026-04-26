#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT

from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest

THIS_DIR = pathlib.Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

import extract_tcp_transport_signatures as extractor  # noqa: E402


class TransportScoringWithSynMetadata(unittest.TestCase):
    def test_syn_metadata_drives_available_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo_root = pathlib.Path(tmp) / "repo"
            fixture_dir = repo_root / "test" / "analysis" / "fixtures" / "imported" / "clienthello" / "android"
            fixture_dir.mkdir(parents=True, exist_ok=True)

            fixture_path = fixture_dir / "chrome_android.clienthello.json"
            fixture_path.write_text(
                json.dumps(
                    {
                        "os_family": "android",
                        "samples": [
                            {
                                "record_lengths": [512],
                                "syn_transport_traits": {
                                    "available": True,
                                    "ttl_bucket": "ttl_33_64",
                                    "mss_bucket": "mss_1201_1460",
                                    "window_scale_bucket": "wscale_6_8",
                                    "syn_option_order_class": "2-4-8-1-3",
                                    "ipid_behavior_class": "nonzero",
                                },
                            },
                            {
                                "record_lengths": [520],
                                "syn_transport_traits": {
                                    "available": True,
                                    "ttl_bucket": "ttl_33_64",
                                    "mss_bucket": "mss_1201_1460",
                                    "window_scale_bucket": "wscale_6_8",
                                    "syn_option_order_class": "2-4-8-1-3",
                                    "ipid_behavior_class": "nonzero",
                                },
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )

            manifest_path = repo_root / "test" / "analysis" / "fixtures" / "imported" / "import_manifest.json"
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            manifest_path.write_text(
                json.dumps(
                    {
                        "entries": [
                            {
                                "profile_id": "chrome_android",
                                "artifacts": {
                                    "clienthello": "test/analysis/fixtures/imported/clienthello/android/chrome_android.clienthello.json"
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            payload = extractor.extract_transport_metrics("2026-04-26T00:00:00Z", repo_root=repo_root)
            self.assertTrue(payload["evidence_scope"]["syn_phase_transport_available"])
            self.assertEqual("available", payload["metric_availability"]["ttl_bucket_match_rate"]["availability"])
            self.assertEqual(1.0, payload["metrics"]["ttl_bucket_match_rate"])
            self.assertEqual(1.0, payload["metrics"]["syn_option_order_class_match_rate"])
            self.assertEqual(1.0, payload["metrics"]["mss_window_scale_bucket_match_rate"])


if __name__ == "__main__":
    unittest.main()
