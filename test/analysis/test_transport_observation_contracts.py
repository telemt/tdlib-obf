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

import extract_tcp_transport_signatures as extractor  # noqa: E402

REPO_ROOT = THIS_DIR.resolve().parents[1]


class TransportObservationContracts(unittest.TestCase):
    def test_unavailable_syn_metrics_are_not_encoded_as_numeric_zeros(self) -> None:
        payload = extractor.extract_transport_metrics("2026-04-26T00:00:00Z", repo_root=REPO_ROOT)
        metrics = payload["metrics"]
        availability = payload["metric_availability"]

        self.assertFalse(payload["evidence_scope"]["syn_phase_transport_available"])
        for metric_name in (
            "ttl_bucket_match_rate",
            "syn_option_order_class_match_rate",
            "mss_window_scale_bucket_match_rate",
        ):
            self.assertIsNone(metrics[metric_name])
            self.assertEqual("unavailable", availability[metric_name]["availability"])
            self.assertEqual("no_syn_phase_data", availability[metric_name]["reason"])

    def test_first_flight_metric_remains_scorable_when_samples_exist(self) -> None:
        payload = extractor.extract_transport_metrics("2026-04-26T00:00:00Z", repo_root=REPO_ROOT)
        metrics = payload["metrics"]
        availability = payload["metric_availability"]

        self.assertEqual("available", availability["first_flight_segmentation_signature_match_rate"]["availability"])
        self.assertIsInstance(metrics["first_flight_segmentation_signature_match_rate"], float)
        self.assertGreaterEqual(metrics["first_flight_segmentation_signature_match_rate"], 0.0)
        self.assertLessEqual(metrics["first_flight_segmentation_signature_match_rate"], 1.0)


if __name__ == "__main__":
    unittest.main()
