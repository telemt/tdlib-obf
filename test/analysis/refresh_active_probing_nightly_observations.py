#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
from typing import Final


SUMMARY_RE: Final[re.Pattern[str]] = re.compile(r"Summary:\s+passed\s+(\d+)/(\d+)\s+selected tests")

SCENARIOS: Final[tuple[tuple[str, str], ...]] = (
    ("selective_drop", "TlsHmacReplayAdversarial"),
    ("reorder_challenge", "RouteEchQuic"),
    ("fallback_route_transition", "TlsRuntimeActivePolicy"),
)


def parse_summary(stdout: str) -> tuple[int, int]:
    match = SUMMARY_RE.search(stdout)
    if match is None:
        raise ValueError("missing test summary line")
    passed = int(match.group(1))
    selected = int(match.group(2))
    if passed < 0 or selected < 0 or passed > selected:
        raise ValueError("invalid test summary counts")
    return passed, selected


def run_scenario(run_all_tests_path: pathlib.Path, filter_name: str) -> tuple[int, int, str]:
    command = [str(run_all_tests_path), "--filter", filter_name]
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    if completed.returncode != 0:
        raise ValueError(f"scenario runner failed for filter {filter_name} with exit code {completed.returncode}")
    passed, selected = parse_summary(stdout + "\n" + stderr)
    return passed, selected - passed, " ".join(command)


def build_payload(run_all_tests_path: pathlib.Path, generated_at_utc: str) -> tuple[dict[str, object], bool]:
    scenarios: dict[str, dict[str, int]] = {}
    source_evidence: list[str] = []
    has_failures = False
    for scenario_name, filter_name in SCENARIOS:
        passed, failed, command_string = run_scenario(run_all_tests_path, filter_name)
        scenarios[scenario_name] = {"passed": passed, "failed": failed}
        source_evidence.append(command_string)
        has_failures = has_failures or failed > 0

    payload: dict[str, object] = {
        "schema_version": 1,
        "generated_at_utc": generated_at_utc,
        "source_lane": "active_probing_nightly",
        "source_evidence": source_evidence,
        "scenarios": scenarios,
        "notes": (
            "Scenario counts are produced from compiled stealth tests that exercise adversarial replay/probing, "
            "route fallback indistinguishability, and runtime active policy route transitions."
        ),
    }
    return payload, has_failures


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Refresh active probing nightly observations from stealth test slices.")
    parser.add_argument(
        "--run-all-tests-path",
        default="build/test/run_all_tests",
        help="Path to the run_all_tests binary",
    )
    parser.add_argument(
        "--output-path",
        default="test/analysis/active_probing_nightly_observations.json",
        help="Path to the output observations JSON",
    )
    parser.add_argument(
        "--generated-at-utc",
        required=True,
        help="RFC3339 UTC timestamp to stamp into the observations file",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    run_all_tests_path = pathlib.Path(args.run_all_tests_path).resolve()
    output_path = pathlib.Path(args.output_path).resolve()

    payload, has_failures = build_payload(run_all_tests_path, args.generated_at_utc)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    return 1 if has_failures else 0


if __name__ == "__main__":
    raise SystemExit(main())