#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs

from __future__ import annotations

import pathlib
import sys
import unittest


THIS_DIR = pathlib.Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

import render_fingerprint_policy_artifacts as policy_artifacts  # noqa: E402


class FingerprintPolicyGenerationAdversarialTest(unittest.TestCase):
    def test_rejects_missing_required_tier(self) -> None:
        spec = {
            "version": 1,
            "tiers": [
                {"tier": "Tier0", "min_authoritative_captures": 0, "min_independent_sources": 0, "min_independent_sessions": 0},
                {"tier": "Tier1", "min_authoritative_captures": 1, "min_independent_sources": 1, "min_independent_sessions": 1},
                {"tier": "Tier2", "min_authoritative_captures": 3, "min_independent_sources": 2, "min_independent_sessions": 2},
                {"tier": "Tier3", "min_authoritative_captures": 15, "min_independent_sources": 3, "min_independent_sessions": 2},
            ],
        }
        with self.assertRaises(ValueError):
            policy_artifacts.validate_tier_spec(spec)

    def test_rejects_threshold_regression_attack(self) -> None:
        spec = {
            "version": 1,
            "tiers": [
                {"tier": "Tier0", "min_authoritative_captures": 0, "min_independent_sources": 0, "min_independent_sessions": 0},
                {"tier": "Tier1", "min_authoritative_captures": 1, "min_independent_sources": 1, "min_independent_sessions": 1},
                {"tier": "Tier2", "min_authoritative_captures": 2, "min_independent_sources": 2, "min_independent_sessions": 2},
                {"tier": "Tier3", "min_authoritative_captures": 10, "min_independent_sources": 3, "min_independent_sessions": 2},
                {"tier": "Tier4", "min_authoritative_captures": 50, "min_independent_sources": 3, "min_independent_sessions": 2},
            ],
        }
        with self.assertRaises(ValueError):
            policy_artifacts.validate_tier_spec(spec)


if __name__ == "__main__":
    unittest.main()
