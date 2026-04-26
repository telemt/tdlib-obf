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
import tempfile
import unittest

THIS_DIR = pathlib.Path(__file__).resolve().parent
import sys

if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

import extract_tcp_transport_signatures as extractor  # noqa: E402


REPO_ROOT = THIS_DIR.resolve().parents[1]
IMPORTED_MANIFEST = THIS_DIR / "fixtures" / "imported" / "import_manifest.json"


class TCPTransportExtractionContract(unittest.TestCase):
    def test_record_lengths_accepts_list_and_single_field_contract(self) -> None:
        self.assertEqual([321, 654], extractor._record_lengths_from_sample({"record_lengths": [321, 654]}))
        self.assertEqual([777], extractor._record_lengths_from_sample({"record_length": 777}))

    def test_collect_first_flight_lengths_contract(self) -> None:
        fixture = {
            "samples": [
                {"record_lengths": [444, 16]},
                {"record_length": 321},
                {"record_lengths": []},
                {},
            ]
        }
        self.assertEqual([444, 321], extractor._collect_first_flight_lengths(fixture))

    def test_compute_segmentation_rate_contract(self) -> None:
        # 99 and 2500 are outside strict bounds; 100 and 2499 are valid.
        values = [99, 100, 2499, 2500]
        # The extractor uses strict inequalities: value > 100 and value < 2500.
        self.assertEqual(0.25, extractor._compute_first_flight_segmentation_rate(values))

    def test_extract_transport_metrics_contract_shape_and_fail_closed(self) -> None:
        payload = extractor.extract_transport_metrics("2026-04-25T00:00:00Z", repo_root=REPO_ROOT)
        self.assertEqual(1, payload["schema_version"])
        self.assertEqual("2026-04-25T00:00:00Z", payload["generated_at_utc"])
        self.assertIn("metrics", payload)
        self.assertIn("metric_availability", payload)
        self.assertIn("evidence_scope", payload)
        self.assertEqual("test/analysis/fixtures/imported/import_manifest.json", payload["source"])
        self.assertFalse(payload["evidence_scope"]["syn_phase_transport_available"])
        self.assertIsNone(payload["metrics"]["ttl_bucket_match_rate"])
        self.assertIsNone(payload["metrics"]["syn_option_order_class_match_rate"])
        self.assertIsNone(payload["metrics"]["mss_window_scale_bucket_match_rate"])
        self.assertEqual(
            "unavailable",
            payload["metric_availability"]["ttl_bucket_match_rate"]["availability"],
        )

    def test_extract_transport_metrics_respects_explicit_repo_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo_root = pathlib.Path(tmp) / "alt-repo"
            fixture_dir = repo_root / "test" / "analysis" / "fixtures" / "imported" / "clienthello"
            fixture_dir.mkdir(parents=True, exist_ok=True)

            fixture_path = fixture_dir / "single.clienthello.json"
            fixture_path.write_text(
                json.dumps(
                    {
                        "samples": [
                            {
                                "record_lengths": [512],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            manifest_path = repo_root / "test" / "analysis" / "fixtures" / "imported" / "import_manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "entries": [
                            {
                                "profile_id": "single",
                                "artifacts": {
                                    "clienthello": "test/analysis/fixtures/imported/clienthello/single.clienthello.json"
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            payload = extractor.extract_transport_metrics("2026-04-25T00:00:00Z", repo_root=repo_root)
            self.assertEqual(1, payload["sample_count"])
            self.assertEqual(1, payload["evidence_scope"]["fixtures_with_first_flight"])
            self.assertEqual(1.0, payload["metrics"]["first_flight_segmentation_signature_match_rate"])

    def test_manifest_has_expected_minimum_sample_count_contract(self) -> None:
        manifest_data = json.loads(IMPORTED_MANIFEST.read_text(encoding="utf-8"))
        entries = manifest_data.get("entries", [])
        self.assertGreaterEqual(len(entries), 99)

    def test_script_generates_observations_json_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            mirror = pathlib.Path(tmp) / "repo"
            shutil.copytree(REPO_ROOT / "test", mirror / "test")
            out_path = mirror / "test" / "analysis" / "transport_coherence_observations.generated.test.json"
            subprocess.check_call(
                [
                    "python3",
                    "test/analysis/extract_tcp_transport_signatures.py",
                    "--repo-root",
                    ".",
                    "--now-utc",
                    "2026-04-25T00:00:00Z",
                    "--output",
                    str(out_path),
                ],
                cwd=mirror,
            )
            output = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertEqual("2026-04-25T00:00:00Z", output["generated_at_utc"])
            self.assertIn("metrics", output)
            self.assertEqual(99, int(output["sample_count"]))

    def test_extraction_chain_is_deterministic_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            mirror = pathlib.Path(tmp) / "repo"
            shutil.copytree(REPO_ROOT / "docs", mirror / "docs")
            shutil.copytree(REPO_ROOT / "test", mirror / "test")

            out_a = mirror / "test" / "analysis" / "transport_coherence_observations.a.json"
            out_b = mirror / "test" / "analysis" / "transport_coherence_observations.b.json"

            for output in (out_a, out_b):
                subprocess.check_call(
                    [
                        "python3",
                        "test/analysis/extract_tcp_transport_signatures.py",
                        "--repo-root",
                        ".",
                        "--now-utc",
                        "2026-04-25T00:00:00Z",
                        "--output",
                        str(output),
                    ],
                    cwd=mirror,
                )

            self.assertEqual(
                json.loads(out_a.read_text(encoding="utf-8")),
                json.loads(out_b.read_text(encoding="utf-8")),
            )


if __name__ == "__main__":
    unittest.main()
