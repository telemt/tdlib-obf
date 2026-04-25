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
from unittest import mock

THIS_DIR = pathlib.Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

import extract_tcp_transport_signatures as extractor  # noqa: E402


class TCPTransportExtractionAdversarial(unittest.TestCase):
    def test_record_lengths_rejects_non_int_values(self) -> None:
        with self.assertRaisesRegex(ValueError, "must be int"):
            extractor._record_lengths_from_sample({"record_lengths": [123, "x"]})

    def test_record_lengths_rejects_zero_or_negative(self) -> None:
        with self.assertRaisesRegex(ValueError, "within"):
            extractor._record_lengths_from_sample({"record_lengths": [0]})
        with self.assertRaisesRegex(ValueError, "within"):
            extractor._record_lengths_from_sample({"record_lengths": [-7]})

    def test_record_lengths_rejects_oversized_value(self) -> None:
        with self.assertRaisesRegex(ValueError, "within"):
            extractor._record_lengths_from_sample({"record_lengths": [70000]})

    def test_collect_first_flight_skips_non_mapping_samples(self) -> None:
        fixture = {
            "samples": [
                {"record_lengths": [512]},
                "not-a-sample",
                123,
                None,
            ]
        }
        self.assertEqual([512], extractor._collect_first_flight_lengths(fixture))

    def test_load_imported_fixtures_rejects_invalid_manifest_shape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            manifest = tmp_path / "import_manifest.json"
            manifest.write_text(json.dumps({"entries": {"bad": "shape"}}), encoding="utf-8")
            with mock.patch.object(extractor, "IMPORTED_MANIFEST_RELATIVE_PATH", pathlib.Path("import_manifest.json")):
                with self.assertRaisesRegex(ValueError, "entries must be a list"):
                    extractor.load_imported_fixtures(tmp_path)

    def test_load_imported_fixtures_rejects_missing_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            manifest = tmp_path / "import_manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "entries": [
                            {
                                "profile_id": "p1",
                                "artifacts": {"clienthello": "test/analysis/fixtures/imported/clienthello/does-not-exist.clienthello.json"},
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.object(extractor, "IMPORTED_MANIFEST_RELATIVE_PATH", pathlib.Path("import_manifest.json")):
                with self.assertRaisesRegex(ValueError, "fixture not found"):
                    extractor.load_imported_fixtures(tmp_path)

    def test_load_imported_fixtures_rejects_path_traversal_outside_repo_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            outside_fixture = tmp_path.parent / "outside.clienthello.json"
            outside_fixture.write_text(json.dumps({"samples": []}), encoding="utf-8")
            manifest = tmp_path / "import_manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "entries": [
                            {
                                "profile_id": "p1",
                                "artifacts": {"clienthello": "../outside.clienthello.json"},
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.object(extractor, "IMPORTED_MANIFEST_RELATIVE_PATH", pathlib.Path("import_manifest.json")):
                with self.assertRaisesRegex(ValueError, "must stay inside repo root"):
                    extractor.load_imported_fixtures(tmp_path)

    def test_extract_transport_metrics_fail_closed_when_no_samples(self) -> None:
        with mock.patch.object(extractor, "load_imported_fixtures", return_value=[]):
            payload = extractor.extract_transport_metrics("2026-04-25T00:00:00Z", repo_root=pathlib.Path("."))
        self.assertEqual(0, payload["sample_count"])
        self.assertEqual(0, payload["evidence_scope"]["first_flight_samples_observed"])
        self.assertEqual(0.0, payload["metrics"]["ttl_bucket_match_rate"])
        self.assertEqual(0.0, payload["metrics"]["syn_option_order_class_match_rate"])
        self.assertEqual(0.0, payload["metrics"]["mss_window_scale_bucket_match_rate"])
        self.assertEqual(0.0, payload["metrics"]["first_flight_segmentation_signature_match_rate"])

    def test_extract_transport_metrics_rejects_malformed_fixture_samples(self) -> None:
        fixtures = [
            {
                "entry": {"profile_id": "good"},
                "fixture": {"samples": [{"record_lengths": [600]}]},
            },
            {
                "entry": {"profile_id": "bad"},
                "fixture": {"samples": [{"record_lengths": ["bad"]}]},
            },
        ]
        with mock.patch.object(extractor, "load_imported_fixtures", return_value=fixtures):
            with self.assertRaisesRegex(ValueError, "must be int"):
                extractor.extract_transport_metrics("2026-04-25T00:00:00Z", repo_root=pathlib.Path("."))


if __name__ == "__main__":
    unittest.main()
