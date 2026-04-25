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

import render_fingerprint_policy_artifacts as policy_artifacts  # noqa: E402


class TransportAndActiveProbingStatusContractTest(unittest.TestCase):
    def test_transport_status_loader_rejects_missing_required_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "transport.json"
            path.write_text(
                json.dumps(
                    {
                        "status": "pass",
                        "generated_at_utc": "2026-04-25T00:00:00Z",
                        "required_metrics": ["ttl_bucket_match_rate"],
                        "metrics": {"ttl_bucket_match_rate": 1.0},
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                policy_artifacts.load_transport_coherence_status(path)

    def test_active_probing_status_loader_rejects_invalid_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "active.json"
            path.write_text(
                json.dumps(
                    {
                        "status": "unknown",
                        "generated_at_utc": "2026-04-25T00:00:00Z",
                        "scenarios": {"drop": {"passed": 1, "failed": 0}},
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                policy_artifacts.load_active_probing_status(path)


if __name__ == "__main__":
    unittest.main()
