#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs

from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest


THIS_DIR = pathlib.Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

import build_transport_coherence_status as status_builder  # noqa: E402


class BuildTransportCoherenceStatusAdversarialTest(unittest.TestCase):
    def test_rejects_nonzero_syn_metrics_when_syn_phase_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "transport_observations.json"
            path.write_text(
                json.dumps(
                    {
                        "sample_count": 99,
                        "metrics": {
                            "ttl_bucket_match_rate": 1.0,
                            "syn_option_order_class_match_rate": 0.0,
                            "mss_window_scale_bucket_match_rate": 0.0,
                            "first_flight_segmentation_signature_match_rate": 1.0,
                        },
                        "power_policy": {
                            "tier2_min_samples": 3,
                            "tier3_min_samples": 15,
                        },
                        "thresholds": {
                            "tier2_min_match_rate": 0.85,
                            "tier3_min_match_rate": 0.95,
                        },
                        "evidence_scope": {
                            "syn_phase_transport_available": False,
                            "first_flight_record_lengths_available": True,
                            "fixtures_with_first_flight": 99,
                            "first_flight_samples_observed": 99,
                        },
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "must stay 0.0 when syn_phase_transport_available is false"):
                status_builder.load_observations(path)

    def test_rejects_invalid_evidence_scope_field_types(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "transport_observations.json"
            path.write_text(
                json.dumps(
                    {
                        "sample_count": 99,
                        "metrics": {
                            "ttl_bucket_match_rate": 0.0,
                            "syn_option_order_class_match_rate": 0.0,
                            "mss_window_scale_bucket_match_rate": 0.0,
                            "first_flight_segmentation_signature_match_rate": 1.0,
                        },
                        "power_policy": {
                            "tier2_min_samples": 3,
                            "tier3_min_samples": 15,
                        },
                        "thresholds": {
                            "tier2_min_match_rate": 0.85,
                            "tier3_min_match_rate": 0.95,
                        },
                        "evidence_scope": {
                            "syn_phase_transport_available": "false",
                            "first_flight_record_lengths_available": True,
                            "fixtures_with_first_flight": 99,
                            "first_flight_samples_observed": 99,
                        },
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "must be a boolean"):
                status_builder.load_observations(path)


if __name__ == "__main__":
    unittest.main()
