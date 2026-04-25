#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs

from __future__ import annotations

import copy
import pathlib
import random
import sys
import unittest


THIS_DIR = pathlib.Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

import render_fingerprint_policy_artifacts as policy_artifacts  # noqa: E402


class FingerprintPolicyGenerationFuzzStressTest(unittest.TestCase):
    def test_light_fuzz_validator_is_fail_closed_on_mutations(self) -> None:
        rng = random.Random(20260425)
        seed = {
            "version": 1,
            "tiers": [
                {"tier": "Tier0", "min_authoritative_captures": 0, "min_independent_sources": 0, "min_independent_sessions": 0},
                {"tier": "Tier1", "min_authoritative_captures": 1, "min_independent_sources": 1, "min_independent_sessions": 1},
                {"tier": "Tier2", "min_authoritative_captures": 3, "min_independent_sources": 2, "min_independent_sessions": 2},
                {"tier": "Tier3", "min_authoritative_captures": 15, "min_independent_sources": 3, "min_independent_sessions": 2},
                {"tier": "Tier4", "min_authoritative_captures": 200, "min_independent_sources": 3, "min_independent_sessions": 2},
            ],
        }

        failures = 0
        for _ in range(250):
            specimen = copy.deepcopy(seed)
            row = rng.choice(specimen["tiers"])
            key = rng.choice([
                "tier",
                "min_authoritative_captures",
                "min_independent_sources",
                "min_independent_sessions",
            ])
            if key == "tier":
                row[key] = f"Tier{rng.randrange(9, 20)}"
            else:
                row[key] = rng.randrange(-10, 60)
            try:
                policy_artifacts.validate_tier_spec(specimen)
            except ValueError:
                failures += 1

        self.assertGreaterEqual(failures, 220, msg="validator must reject most random mutations")

    def test_stress_repeated_render_is_byte_deterministic(self) -> None:
        spec = {
            "version": 1,
            "tiers": [
                {"tier": "Tier0", "min_authoritative_captures": 0, "min_independent_sources": 0, "min_independent_sessions": 0},
                {"tier": "Tier1", "min_authoritative_captures": 1, "min_independent_sources": 1, "min_independent_sessions": 1},
                {"tier": "Tier2", "min_authoritative_captures": 3, "min_independent_sources": 2, "min_independent_sessions": 2},
                {"tier": "Tier3", "min_authoritative_captures": 15, "min_independent_sources": 3, "min_independent_sessions": 2},
                {"tier": "Tier4", "min_authoritative_captures": 200, "min_independent_sources": 3, "min_independent_sessions": 2},
            ],
        }
        rendered = policy_artifacts.render_trust_tier_markdown_block(spec)
        for _ in range(500):
            self.assertEqual(rendered, policy_artifacts.render_trust_tier_markdown_block(spec))


if __name__ == "__main__":
    unittest.main()
