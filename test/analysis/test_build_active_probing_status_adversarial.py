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

import build_active_probing_status as status_builder  # noqa: E402


class BuildActiveProbingStatusAdversarialTest(unittest.TestCase):
    def test_rejects_missing_required_scenario(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "active_observations.json"
            path.write_text(
                json.dumps(
                    {
                        "generated_at_utc": "2026-04-25T00:00:00Z",
                        "source_lane": "active_probing_nightly",
                        "scenarios": {
                            "selective_drop": {"passed": 11, "failed": 0},
                            "reorder_challenge": {"passed": 7, "failed": 0},
                        },
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "missing required scenarios"):
                status_builder.load_observations(path)

    def test_accepts_all_required_scenarios(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "active_observations.json"
            path.write_text(
                json.dumps(
                    {
                        "generated_at_utc": "2026-04-25T00:00:00Z",
                        "source_lane": "active_probing_nightly",
                        "scenarios": {
                            "selective_drop": {"passed": 11, "failed": 0},
                            "reorder_challenge": {"passed": 7, "failed": 0},
                            "fallback_route_transition": {"passed": 3, "failed": 0},
                        },
                    }
                ),
                encoding="utf-8",
            )
            loaded = status_builder.load_observations(path)
            self.assertIn("fallback_route_transition", loaded["scenarios"])

    def test_pending_status_when_scenario_has_zero_passed_and_zero_failed(self) -> None:
        observations = {
            "generated_at_utc": "2026-04-25T00:00:00Z",
            "source_lane": "active_probing_nightly",
            "scenarios": {
                "selective_drop": {"passed": 11, "failed": 0},
                "reorder_challenge": {"passed": 0, "failed": 0},
                "fallback_route_transition": {"passed": 3, "failed": 0},
            },
            "source_evidence": ["./build/test/run_all_tests --filter RouteEchQuic"],
        }

        payload = status_builder.build_payload(
            now_utc="2026-04-25T00:00:00Z",
            observations=observations,
            observation_input_path=pathlib.Path("test/analysis/active_probing_nightly_observations.json"),
        )

        self.assertEqual("pending", payload["status"])


if __name__ == "__main__":
    unittest.main()
