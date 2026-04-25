#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs

from __future__ import annotations

import argparse
import json
import pathlib
from typing import Any


DEFAULT_OBSERVATIONS_RELATIVE_PATH = pathlib.Path("test/analysis/active_probing_nightly_observations.json")
REQUIRED_SCENARIOS = (
    "selective_drop",
    "reorder_challenge",
    "fallback_route_transition",
)


def _must_be_mapping(value: Any, field_name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{field_name} must be an object")
    return value


def _must_be_non_negative_int(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or value < 0:
        raise ValueError(f"{field_name} must be a non-negative integer")
    return value


def load_observations(path: pathlib.Path) -> dict[str, Any]:
    loaded = _must_be_mapping(json.loads(path.read_text(encoding="utf-8")), "active probing observations")
    scenarios = _must_be_mapping(loaded.get("scenarios"), "active probing observations.scenarios")
    if not scenarios:
        raise ValueError("active probing observations.scenarios must contain at least one scenario")
    missing_scenarios = [name for name in REQUIRED_SCENARIOS if name not in scenarios]
    if missing_scenarios:
        raise ValueError(
            "active probing observations.scenarios missing required scenarios: " + ", ".join(missing_scenarios)
        )
    for scenario_name, scenario_payload in scenarios.items():
        scenario = _must_be_mapping(scenario_payload, f"active probing observations.scenarios.{scenario_name}")
        _must_be_non_negative_int(scenario.get("passed"), f"active probing observations.scenarios.{scenario_name}.passed")
        _must_be_non_negative_int(scenario.get("failed"), f"active probing observations.scenarios.{scenario_name}.failed")
    source_evidence = loaded.get("source_evidence")
    if source_evidence is not None:
        if not isinstance(source_evidence, list) or not source_evidence:
            raise ValueError("active probing observations.source_evidence must be a non-empty list when present")
    return loaded


def build_payload(now_utc: str, observations: dict[str, Any], observation_input_path: pathlib.Path) -> dict[str, Any]:
    scenarios = _must_be_mapping(observations.get("scenarios"), "active probing observations.scenarios")
    has_failures = False
    has_passed_coverage = True
    for scenario_payload in scenarios.values():
        scenario = _must_be_mapping(scenario_payload, "active probing observations.scenario")
        passed = int(scenario.get("passed", 0))
        failed = int(scenario.get("failed", 0))
        has_failures = has_failures or failed > 0
        has_passed_coverage = has_passed_coverage and passed > 0
    if has_failures:
        status = "fail"
    elif has_passed_coverage:
        status = "pass"
    else:
        status = "pending"

    return {
        "status": status,
        "generated_at_utc": now_utc,
        "source_lane": str(observations.get("source_lane", "active_probing_nightly")),
        "observation_input_path": str(observation_input_path.as_posix()),
        "observation_generated_at_utc": str(observations.get("generated_at_utc", "")),
        "scenarios": scenarios,
        "source_evidence": observations.get("source_evidence", []),
        "notes": str(observations.get("notes", "")),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build active probing status artifact from measured observations.")
    parser.add_argument("--repo-root", required=True, help="Repository root path")
    parser.add_argument("--now-utc", required=True, help="Deterministic UTC timestamp (RFC3339 Z)")
    parser.add_argument(
        "--observations-path",
        default=str(DEFAULT_OBSERVATIONS_RELATIVE_PATH),
        help="Path to active probing observations JSON (absolute or repo-relative)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = pathlib.Path(args.repo_root).resolve()
    observation_input_path = pathlib.Path(args.observations_path)
    if not observation_input_path.is_absolute():
        observation_input_path = (repo_root / observation_input_path).resolve()
    observations = load_observations(observation_input_path)
    out_path = repo_root / "docs" / "Documentation" / "FINGERPRINT_ACTIVE_PROBING_NIGHTLY_STATUS.generated.json"
    payload = build_payload(args.now_utc, observations, observation_input_path.relative_to(repo_root))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
