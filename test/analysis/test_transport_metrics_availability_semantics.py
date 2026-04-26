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

import build_transport_coherence_status as status_builder  # noqa: E402


class TransportMetricsAvailabilitySemantics(unittest.TestCase):
    def test_load_observations_accepts_unavailable_syn_metrics_with_null_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "transport_observations.json"
            path.write_text(
                json.dumps(
                    {
                        "sample_count": 99,
                        "metrics": {
                            "ttl_bucket_match_rate": None,
                            "syn_option_order_class_match_rate": None,
                            "mss_window_scale_bucket_match_rate": None,
                            "first_flight_segmentation_signature_match_rate": 1.0,
                        },
                        "metric_availability": {
                            "ttl_bucket_match_rate": {"availability": "unavailable", "reason": "no_syn_phase_data"},
                            "syn_option_order_class_match_rate": {"availability": "unavailable", "reason": "no_syn_phase_data"},
                            "mss_window_scale_bucket_match_rate": {"availability": "unavailable", "reason": "no_syn_phase_data"},
                            "first_flight_segmentation_signature_match_rate": {"availability": "available"},
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
                            "first_flight_samples_observed": 540,
                        },
                    }
                ),
                encoding="utf-8",
            )
            loaded = status_builder.load_observations(path)
            self.assertEqual("unavailable", loaded["metric_availability"]["ttl_bucket_match_rate"]["availability"])
            self.assertIsNone(loaded["metrics"]["ttl_bucket_match_rate"])

    def test_build_payload_marks_tier_gates_not_scorable_when_syn_metrics_unavailable(self) -> None:
        observations = {
            "sample_count": 99,
            "metrics": {
                "ttl_bucket_match_rate": None,
                "syn_option_order_class_match_rate": None,
                "mss_window_scale_bucket_match_rate": None,
                "first_flight_segmentation_signature_match_rate": 1.0,
            },
            "metric_availability": {
                "ttl_bucket_match_rate": {"availability": "unavailable", "reason": "no_syn_phase_data"},
                "syn_option_order_class_match_rate": {"availability": "unavailable", "reason": "no_syn_phase_data"},
                "mss_window_scale_bucket_match_rate": {"availability": "unavailable", "reason": "no_syn_phase_data"},
                "first_flight_segmentation_signature_match_rate": {"availability": "available"},
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
                "first_flight_samples_observed": 540,
            },
        }

        payload = status_builder.build_payload(
            "2026-04-26T00:00:00Z",
            observations,
            pathlib.Path("test/analysis/transport_coherence_observations.json"),
        )
        self.assertEqual("pending", payload["status"])
        self.assertFalse(payload["gate_evaluation"]["tier2"]["scorable"])
        self.assertIn("ttl_bucket_match_rate", payload["gate_evaluation"]["tier2"]["unavailable_metrics"])


if __name__ == "__main__":
    unittest.main()
