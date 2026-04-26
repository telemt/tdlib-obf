#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT

from __future__ import annotations

import json
import pathlib
import subprocess
import tempfile
import unittest

THIS_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = THIS_DIR.resolve().parents[1]


class TransportStatusBuilderWithUnavailableSyn(unittest.TestCase):
    def test_status_builder_reports_not_scorable_instead_of_failing_syn_zero_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            observations_path = pathlib.Path(tmp) / "transport_observations.json"
            observations_path.write_text(
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
                        "generated_at_utc": "2026-04-26T00:00:00Z",
                    }
                ),
                encoding="utf-8",
            )

            subprocess.check_call(
                [
                    "python3",
                    "test/analysis/build_transport_coherence_status.py",
                    "--repo-root",
                    ".",
                    "--now-utc",
                    "2026-04-26T00:00:00Z",
                    "--observations-path",
                    str(observations_path),
                ],
                cwd=REPO_ROOT,
            )

            status_path = REPO_ROOT / "docs" / "Generated" / "FINGERPRINT_TRANSPORT_COHERENCE_STATUS.generated.json"
            payload = json.loads(status_path.read_text(encoding="utf-8"))

        self.assertEqual("pending", payload["status"])
        self.assertFalse(payload["gate_evaluation"]["tier2"]["scorable"])
        self.assertEqual("not_scorable_unavailable_metrics", payload["gate_evaluation"]["tier2"]["reason"])


if __name__ == "__main__":
    unittest.main()
