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


REQUIRED_METRICS = (
    "ttl_bucket_match_rate",
    "syn_option_order_class_match_rate",
    "mss_window_scale_bucket_match_rate",
    "first_flight_segmentation_signature_match_rate",
)

DEFAULT_OBSERVATIONS_RELATIVE_PATH = pathlib.Path("test/analysis/transport_coherence_observations.json")


def _must_be_mapping(value: Any, field_name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{field_name} must be an object")
    return value


def _must_be_non_negative_int(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or value < 0:
        raise ValueError(f"{field_name} must be a non-negative integer")
    return value


def _must_be_bool(value: Any, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{field_name} must be a boolean")
    return value


def _must_be_rate(value: Any, field_name: str) -> float:
    if not isinstance(value, (int, float)):
        raise ValueError(f"{field_name} must be numeric")
    parsed = float(value)
    if parsed < 0.0 or parsed > 1.0:
        raise ValueError(f"{field_name} must be in [0.0, 1.0]")
    return parsed


def load_observations(path: pathlib.Path) -> dict[str, Any]:
    loaded = _must_be_mapping(json.loads(path.read_text(encoding="utf-8")), "transport observations")
    metrics = _must_be_mapping(loaded.get("metrics"), "transport observations.metrics")
    for metric_name in REQUIRED_METRICS:
        _must_be_rate(metrics.get(metric_name), f"transport observations.metrics.{metric_name}")
    sample_count = _must_be_non_negative_int(loaded.get("sample_count"), "transport observations.sample_count")
    power_policy = _must_be_mapping(loaded.get("power_policy"), "transport observations.power_policy")
    _must_be_non_negative_int(power_policy.get("tier2_min_samples"), "transport observations.power_policy.tier2_min_samples")
    _must_be_non_negative_int(power_policy.get("tier3_min_samples"), "transport observations.power_policy.tier3_min_samples")
    thresholds = _must_be_mapping(loaded.get("thresholds"), "transport observations.thresholds")
    _must_be_rate(thresholds.get("tier2_min_match_rate"), "transport observations.thresholds.tier2_min_match_rate")
    _must_be_rate(thresholds.get("tier3_min_match_rate"), "transport observations.thresholds.tier3_min_match_rate")
    evidence_scope = loaded.get("evidence_scope")
    if evidence_scope is not None:
        evidence_scope = _must_be_mapping(evidence_scope, "transport observations.evidence_scope")
        syn_phase_transport_available = _must_be_bool(
            evidence_scope.get("syn_phase_transport_available"),
            "transport observations.evidence_scope.syn_phase_transport_available",
        )
        _must_be_bool(
            evidence_scope.get("first_flight_record_lengths_available"),
            "transport observations.evidence_scope.first_flight_record_lengths_available",
        )
        _must_be_non_negative_int(
            evidence_scope.get("fixtures_with_first_flight"),
            "transport observations.evidence_scope.fixtures_with_first_flight",
        )
        _must_be_non_negative_int(
            evidence_scope.get("first_flight_samples_observed"),
            "transport observations.evidence_scope.first_flight_samples_observed",
        )
        if not syn_phase_transport_available:
            for metric_name in (
                "ttl_bucket_match_rate",
                "syn_option_order_class_match_rate",
                "mss_window_scale_bucket_match_rate",
            ):
                if float(metrics.get(metric_name, 0.0)) != 0.0:
                    raise ValueError(
                        f"transport observations.metrics.{metric_name} must stay 0.0 when syn_phase_transport_available is false"
                    )
    loaded["sample_count"] = sample_count
    return loaded


def _gate_passed(metrics: dict[str, Any], threshold: float) -> bool:
    for metric_name in REQUIRED_METRICS:
        if float(metrics[metric_name]) < threshold:
            return False
    return True


def build_payload(now_utc: str, observations: dict[str, Any], observation_input_path: pathlib.Path) -> dict[str, Any]:
    metrics = dict(observations["metrics"])
    power_policy = dict(observations["power_policy"])
    thresholds = dict(observations["thresholds"])

    tier2_min_samples = int(power_policy["tier2_min_samples"])
    tier3_min_samples = int(power_policy["tier3_min_samples"])
    tier2_threshold = float(thresholds["tier2_min_match_rate"])
    tier3_threshold = float(thresholds["tier3_min_match_rate"])

    sample_count = int(observations["sample_count"])
    tier2_eligible = sample_count >= tier2_min_samples
    tier3_eligible = sample_count >= tier3_min_samples
    tier2_passed = tier2_eligible and _gate_passed(metrics, tier2_threshold)
    tier3_passed = tier3_eligible and _gate_passed(metrics, tier3_threshold)

    if tier2_passed:
        status = "pass"
    elif tier2_eligible:
        status = "fail"
    else:
        status = "pending"

    return {
        "status": status,
        "generated_at_utc": now_utc,
        "required_metrics": list(REQUIRED_METRICS),
        "metrics": metrics,
        "sample_count": sample_count,
        "observation_input_path": str(observation_input_path.as_posix()),
        "observation_generated_at_utc": str(observations.get("generated_at_utc", "")),
        "source_lanes": [
            "transport_coherence_baseline",
            "transport_coherence_adversarial_smoke",
        ],
        "gate_evaluation": {
            "tier2": {
                "eligible": tier2_eligible,
                "passed": tier2_passed,
                "min_samples": tier2_min_samples,
                "min_match_rate": tier2_threshold,
            },
            "tier3": {
                "eligible": tier3_eligible,
                "passed": tier3_passed,
                "min_samples": tier3_min_samples,
                "min_match_rate": tier3_threshold,
            },
        },
        "evidence_scope": dict(observations.get("evidence_scope", {})),
        "notes": str(observations.get("notes", "")),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build transport coherence status artifact from measured observations.")
    parser.add_argument("--repo-root", required=True, help="Repository root path")
    parser.add_argument("--now-utc", required=True, help="Deterministic UTC timestamp (RFC3339 Z)")
    parser.add_argument(
        "--observations-path",
        default=str(DEFAULT_OBSERVATIONS_RELATIVE_PATH),
        help="Path to transport coherence observations JSON (absolute or repo-relative)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = pathlib.Path(args.repo_root).resolve()
    observation_input_path = pathlib.Path(args.observations_path)
    if not observation_input_path.is_absolute():
        observation_input_path = (repo_root / observation_input_path).resolve()
    observations = load_observations(observation_input_path)
    out_path = repo_root / "docs" / "Documentation" / "FINGERPRINT_TRANSPORT_COHERENCE_STATUS.generated.json"
    payload = build_payload(args.now_utc, observations, observation_input_path.relative_to(repo_root))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
