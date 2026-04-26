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
REPO_ROOT = THIS_DIR.parents[1]


class TCPTransportExtractionIntegration(unittest.TestCase):
    def test_extraction_to_status_pipeline_is_reproducible(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            mirror = pathlib.Path(tmp) / "repo"
            shutil.copytree(REPO_ROOT / "docs", mirror / "docs")
            shutil.copytree(REPO_ROOT / "test", mirror / "test")

            observations_path = mirror / "test" / "analysis" / "transport_coherence_observations.json"

            subprocess.check_call(
                [
                    "python3",
                    "test/analysis/extract_tcp_transport_signatures.py",
                    "--repo-root",
                    ".",
                    "--now-utc",
                    "2026-04-25T00:00:00Z",
                    "--output",
                    str(observations_path),
                ],
                cwd=mirror,
            )
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

            status_path = mirror / "docs" / "Generated" / "FINGERPRINT_TRANSPORT_COHERENCE_STATUS.generated.json"
            status = json.loads(status_path.read_text(encoding="utf-8"))
            self.assertEqual("pending", status["status"])
            self.assertEqual(99, int(status["sample_count"]))
            self.assertIn("gate_evaluation", status)
            self.assertIn("tier2", status["gate_evaluation"])

    def test_active_probing_status_pipeline_is_reproducible(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            mirror = pathlib.Path(tmp) / "repo"
            shutil.copytree(REPO_ROOT / "docs", mirror / "docs")
            shutil.copytree(REPO_ROOT / "test", mirror / "test")

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

            status_path = mirror / "docs" / "Generated" / "FINGERPRINT_ACTIVE_PROBING_NIGHTLY_STATUS.generated.json"
            status = json.loads(status_path.read_text(encoding="utf-8"))
            self.assertEqual("pass", status["status"])
            self.assertIn("selective_drop", status["scenarios"])


if __name__ == "__main__":
    unittest.main()
