#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs

from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest


THIS_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = THIS_DIR.parents[1]
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

import render_fingerprint_policy_artifacts as policy_artifacts  # noqa: E402


class FingerprintPolicyGenerationIntegrationTest(unittest.TestCase):
    def test_generate_artifacts_writes_summary_and_updates_docs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = pathlib.Path(tmp)
            mirror = tmp_root / "repo"
            shutil.copytree(REPO_ROOT / "docs", mirror / "docs")
            shutil.copytree(REPO_ROOT / "test", mirror / "test")

            outputs = policy_artifacts.generate_artifacts(mirror)
            summary_path = pathlib.Path(outputs["release_evidence_summary_path"])
            self.assertTrue(summary_path.exists())

            for rel in (
                "docs/Documentation/FINGERPRINT_DOCUMENTATION_INDEX.md",
                "docs/Documentation/FINGERPRINT_GENERATION_PIPELINE.md",
                "docs/Documentation/FINGERPRINT_OPERATIONS_GUIDE.md",
            ):
                text = (mirror / rel).read_text(encoding="utf-8")
                self.assertIn(policy_artifacts.GENERATED_BLOCK_BEGIN, text)
                self.assertIn(policy_artifacts.GENERATED_BLOCK_END, text)

    def test_forged_transport_observations_are_rejected_and_fail_status_propagates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = pathlib.Path(tmp)
            mirror = tmp_root / "repo"
            shutil.copytree(REPO_ROOT / "docs", mirror / "docs")
            shutil.copytree(REPO_ROOT / "test", mirror / "test")

            observations_path = mirror / "test" / "analysis" / "transport_coherence_observations.json"
            forged_observations = {
                "schema_version": 1,
                "generated_at_utc": "2026-04-25T00:00:00Z",
                "source": "test/analysis/fixtures/imported/import_manifest.json",
                "sample_count": 99,
                "method": "forged metrics",
                "power_policy": {
                    "tier2_min_samples": 3,
                    "tier3_min_samples": 15,
                },
                "thresholds": {
                    "tier2_min_match_rate": 0.85,
                    "tier3_min_match_rate": 0.95,
                },
                "metrics": {
                    "ttl_bucket_match_rate": 1.0,
                    "syn_option_order_class_match_rate": 0.0,
                    "mss_window_scale_bucket_match_rate": 0.0,
                    "first_flight_segmentation_signature_match_rate": 1.0,
                },
                "metric_availability": {
                    "ttl_bucket_match_rate": {
                        "availability": "unavailable",
                        "reason": "no_syn_phase_data",
                    },
                    "syn_option_order_class_match_rate": {
                        "availability": "unavailable",
                        "reason": "no_syn_phase_data",
                    },
                    "mss_window_scale_bucket_match_rate": {
                        "availability": "unavailable",
                        "reason": "no_syn_phase_data",
                    },
                    "first_flight_segmentation_signature_match_rate": {
                        "availability": "available",
                    },
                },
                "evidence_scope": {
                    "syn_phase_transport_available": False,
                    "first_flight_record_lengths_available": True,
                    "fixtures_with_first_flight": 99,
                    "first_flight_samples_observed": 99,
                },
                "notes": "tampered",
            }
            observations_path.write_text(json.dumps(forged_observations), encoding="utf-8")

            rejected = subprocess.run(
                [
                    "python3",
                    "test/analysis/build_transport_coherence_status.py",
                    "--repo-root",
                    ".",
                    "--now-utc",
                    "2026-04-25T00:00:00Z",
                ],
                cwd=mirror,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(0, rejected.returncode)
            self.assertIn(
                "must be null when metric availability is unavailable",
                rejected.stderr,
            )

            corrected_fail_observations = dict(forged_observations)
            corrected_fail_observations["metrics"] = {
                "ttl_bucket_match_rate": None,
                "syn_option_order_class_match_rate": None,
                "mss_window_scale_bucket_match_rate": None,
                "first_flight_segmentation_signature_match_rate": 1.0,
            }
            observations_path.write_text(json.dumps(corrected_fail_observations), encoding="utf-8")

            subprocess.check_call(
                [
                    "python3",
                    "test/analysis/build_transport_coherence_status.py",
                    "--repo-root",
                    ".",
                    "--now-utc",
                    "2026-04-25T00:00:00Z",
                ],
                cwd=mirror,
            )

            outputs = policy_artifacts.generate_artifacts(mirror, now_utc="2026-04-25T00:00:00Z")
            summary_path = pathlib.Path(outputs["release_evidence_summary_path"])
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertEqual("pending", summary["transport_coherence_status"]["status"])
            self.assertIsNone(summary["transport_coherence_status"]["metrics"]["ttl_bucket_match_rate"])


if __name__ == "__main__":
    unittest.main()
