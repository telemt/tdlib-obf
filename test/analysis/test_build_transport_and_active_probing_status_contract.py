#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs

from __future__ import annotations

import pathlib
import shutil
import subprocess
import tempfile
import unittest


THIS_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = THIS_DIR.parents[1]


class BuildTransportAndActiveProbingStatusContractTest(unittest.TestCase):
    def test_generators_emit_required_status_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            mirror = pathlib.Path(tmp) / "repo"
            shutil.copytree(REPO_ROOT / "docs", mirror / "docs")
            shutil.copytree(REPO_ROOT / "test", mirror / "test")

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
            subprocess.check_call(
                [
                    "python3",
                    "test/analysis/build_active_probing_status.py",
                    "--repo-root",
                    ".",
                    "--now-utc",
                    "2026-04-25T00:00:00Z",
                ],
                cwd=mirror,
            )

            transport_path = mirror / "docs" / "Generated" / "FINGERPRINT_TRANSPORT_COHERENCE_STATUS.generated.json"
            active_path = mirror / "docs" / "Generated" / "FINGERPRINT_ACTIVE_PROBING_NIGHTLY_STATUS.generated.json"
            self.assertTrue(transport_path.exists())
            self.assertTrue(active_path.exists())

            transport_text = transport_path.read_text(encoding="utf-8")
            active_text = active_path.read_text(encoding="utf-8")
            self.assertIn('"status": "pending"', transport_text)
            self.assertIn('"ttl_bucket_match_rate"', transport_text)
            self.assertIn('"observation_input_path"', transport_text)
            self.assertIn('"sample_count"', transport_text)
            self.assertIn('"gate_evaluation"', transport_text)
            self.assertNotIn('"method": "Transport signature inference', transport_text)
            self.assertNotIn('Inferred from known browser TCP profiles', transport_text)
            self.assertIn('"syn_phase_transport_available": false', transport_text)
            self.assertIn('"status": "pass"', active_text)
            self.assertIn('"selective_drop"', active_text)
            self.assertIn('"observation_input_path"', active_text)
            self.assertIn('"source_evidence"', active_text)


if __name__ == "__main__":
    unittest.main()
