#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs

"""Extract transport-coherence observations from imported ClientHello fixtures.

Security model:
1. Treat fixture content as untrusted input and validate all fields before use.
2. Never synthesize transport-layer evidence that does not exist in fixtures.
3. Fail closed when SYN/TTL/MSS/window-scale evidence is unavailable.

Current corpus limitation:
Imported ClientHello fixtures start at TLS records and do not include SYN-phase
transport metadata. Therefore, this extractor computes first-flight TLS
record segmentation metrics from observed data and marks SYN-phase transport
metrics as unavailable instead of synthesizing numeric placeholders.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import sys
from typing import Any


THIS_DIR = pathlib.Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

REPO_ROOT = THIS_DIR.resolve().parents[1]
IMPORTED_MANIFEST_RELATIVE_PATH = pathlib.Path("test/analysis/fixtures/imported/import_manifest.json")
DEFAULT_OUTPUT = THIS_DIR / "transport_coherence_observations.json"
MIN_REALISTIC_TLS_RECORD_LENGTH = 100
MAX_REALISTIC_TLS_RECORD_LENGTH = 2500
UNAVAILABLE_REASON_NO_SYN_PHASE_DATA = "no_syn_phase_data"

SYN_PHASE_METRIC_NAMES = (
    "ttl_bucket_match_rate",
    "syn_option_order_class_match_rate",
    "mss_window_scale_bucket_match_rate",
)
FIRST_FLIGHT_METRIC_NAME = "first_flight_segmentation_signature_match_rate"


def _safe_os_family(value: Any) -> str:
    if isinstance(value, str) and value.strip():
        return value.strip().lower()
    return "unknown"


def _extract_syn_trait_sample(sample: dict[str, Any], os_family: str) -> dict[str, str] | None:
    raw_traits = sample.get("syn_transport_traits")
    if not isinstance(raw_traits, dict):
        return None
    if raw_traits.get("available") is not True:
        return None

    ttl_bucket = raw_traits.get("ttl_bucket")
    option_order = raw_traits.get("syn_option_order_class")
    mss_bucket = raw_traits.get("mss_bucket")
    window_scale_bucket = raw_traits.get("window_scale_bucket")
    if not all(isinstance(value, str) and value for value in (ttl_bucket, option_order, mss_bucket, window_scale_bucket)):
        raise ValueError("available syn_transport_traits must include ttl_bucket, syn_option_order_class, mss_bucket, window_scale_bucket")

    return {
        "os_family": os_family,
        "ttl_bucket": ttl_bucket,
        "syn_option_order_class": option_order,
        "mss_window_scale_bucket": f"{mss_bucket}/{window_scale_bucket}",
    }


def _modal_value(values: list[str]) -> str:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))[0][0]


def _compute_os_modal_match_rate(samples: list[dict[str, str]], key: str) -> tuple[float | None, int]:
    if not samples:
        return None, 0

    values_by_os: dict[str, list[str]] = {}
    for sample in samples:
        values_by_os.setdefault(sample["os_family"], []).append(sample[key])

    baseline_by_os = {os_family: _modal_value(values) for os_family, values in values_by_os.items()}

    matches = 0
    for sample in samples:
        if sample[key] == baseline_by_os[sample["os_family"]]:
            matches += 1
    return round(matches / len(samples), 6), len(samples)


def _must_be_mapping(value: Any, field_name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{field_name} must be an object")
    return value


def _record_lengths_from_sample(sample: dict[str, Any]) -> list[int]:
    raw_lengths = sample.get("record_lengths")
    if isinstance(raw_lengths, list) and raw_lengths:
        result: list[int] = []
        for index, raw in enumerate(raw_lengths):
            if not isinstance(raw, int):
                raise ValueError(f"sample.record_lengths[{index}] must be int")
            if raw <= 0 or raw > 65535:
                raise ValueError("sample.record_lengths values must be within (0, 65535]")
            result.append(raw)
        return result

    single = sample.get("record_length")
    if isinstance(single, int) and 0 < single <= 65535:
        return [single]

    return []


def _collect_first_flight_lengths(fixture: dict[str, Any]) -> list[int]:
    samples = fixture.get("samples")
    if not isinstance(samples, list):
        return []

    first_flight_lengths: list[int] = []
    for raw_sample in samples:
        if not isinstance(raw_sample, dict):
            continue
        lengths = _record_lengths_from_sample(raw_sample)
        if lengths:
            first_flight_lengths.append(lengths[0])
    return first_flight_lengths


def _compute_first_flight_segmentation_rate(first_flight_lengths: list[int]) -> float:
    if not first_flight_lengths:
        return 0.0
    realistic = sum(
        1
        for value in first_flight_lengths
        if MIN_REALISTIC_TLS_RECORD_LENGTH < value < MAX_REALISTIC_TLS_RECORD_LENGTH
    )
    return round(realistic / len(first_flight_lengths), 6)


def load_imported_fixtures(repo_root: pathlib.Path, manifest_path: pathlib.Path | None = None) -> list[dict[str, Any]]:
    """Load all imported ClientHello fixtures from manifest."""
    resolved_repo_root = repo_root.resolve()
    resolved_manifest_path = manifest_path if manifest_path is not None else (resolved_repo_root / IMPORTED_MANIFEST_RELATIVE_PATH)
    if not resolved_manifest_path.exists():
        raise ValueError(f"import manifest not found: {resolved_manifest_path}")

    manifest = _must_be_mapping(json.loads(resolved_manifest_path.read_text(encoding="utf-8")), "import manifest")
    raw_entries = manifest.get("entries")
    if not isinstance(raw_entries, list):
        raise ValueError("import manifest entries must be a list")

    fixtures: list[dict[str, Any]] = []
    for entry_index, raw_entry in enumerate(raw_entries):
        if not isinstance(raw_entry, dict):
            raise ValueError(f"import manifest entries[{entry_index}] must be an object")
        artifacts = raw_entry.get("artifacts")
        if not isinstance(artifacts, dict):
            raise ValueError(f"import manifest entries[{entry_index}].artifacts must be an object")
        clienthello_path = artifacts.get("clienthello")
        if not isinstance(clienthello_path, str) or not clienthello_path:
            raise ValueError(f"import manifest entries[{entry_index}].artifacts.clienthello must be a non-empty string")

        fixture_path = (resolved_repo_root / clienthello_path).resolve()
        try:
            fixture_path.relative_to(resolved_repo_root)
        except ValueError as exc:
            raise ValueError(
                f"import manifest entries[{entry_index}].artifacts.clienthello must stay inside repo root"
            ) from exc
        if not fixture_path.exists():
            raise ValueError(f"fixture not found: {fixture_path}")

        fixture_data = _must_be_mapping(json.loads(fixture_path.read_text(encoding="utf-8")), f"fixture {clienthello_path}")
        fixtures.append({"entry": raw_entry, "fixture": fixture_data})
    return fixtures


def extract_transport_metrics(now_utc: str, repo_root: pathlib.Path) -> dict[str, Any]:
    """Extract transport coherence metrics from imported fixtures."""

    resolved_repo_root = repo_root.resolve()
    manifest_path = resolved_repo_root / IMPORTED_MANIFEST_RELATIVE_PATH
    fixtures = load_imported_fixtures(resolved_repo_root, manifest_path)
    print(f"Loaded {len(fixtures)} fixtures", file=sys.stderr)

    first_flight_lengths: list[int] = []
    fixtures_with_first_flight = 0
    syn_trait_samples: list[dict[str, str]] = []
    for entry_data in fixtures:
        fixture = entry_data["fixture"]
        lengths = _collect_first_flight_lengths(fixture)
        if lengths:
            fixtures_with_first_flight += 1
            first_flight_lengths.extend(lengths)

        os_family = _safe_os_family(fixture.get("os_family"))
        raw_samples = fixture.get("samples")
        if isinstance(raw_samples, list):
            for raw_sample in raw_samples:
                if not isinstance(raw_sample, dict):
                    continue
                traits = _extract_syn_trait_sample(raw_sample, os_family)
                if traits is not None:
                    syn_trait_samples.append(traits)

    ttl_match_rate, ttl_scorable = _compute_os_modal_match_rate(syn_trait_samples, "ttl_bucket")
    option_match_rate, option_scorable = _compute_os_modal_match_rate(syn_trait_samples, "syn_option_order_class")
    mss_ws_match_rate, mss_ws_scorable = _compute_os_modal_match_rate(syn_trait_samples, "mss_window_scale_bucket")

    def availability_payload(scorable_count: int) -> dict[str, str]:
        if scorable_count > 0:
            return {"availability": "available"}
        return {
            "availability": "unavailable",
            "reason": UNAVAILABLE_REASON_NO_SYN_PHASE_DATA,
        }

    metrics = {
        "ttl_bucket_match_rate": ttl_match_rate,
        "syn_option_order_class_match_rate": option_match_rate,
        "mss_window_scale_bucket_match_rate": mss_ws_match_rate,
        "first_flight_segmentation_signature_match_rate": _compute_first_flight_segmentation_rate(first_flight_lengths),
    }
    metric_availability = {
        "ttl_bucket_match_rate": availability_payload(ttl_scorable),
        "syn_option_order_class_match_rate": availability_payload(option_scorable),
        "mss_window_scale_bucket_match_rate": availability_payload(mss_ws_scorable),
        "first_flight_segmentation_signature_match_rate": {
            "availability": "available",
        },
    }

    return {
        "schema_version": 1,
        "generated_at_utc": now_utc,
        "source": str(IMPORTED_MANIFEST_RELATIVE_PATH.as_posix()),
        "sample_count": len(fixtures),
        "method": "Observed first-flight record-length and SYN trait extraction from imported ClientHello fixtures; unavailable SYN-phase metrics are marked unavailable and never synthesized as numeric values.",
        "power_policy": {
            "tier2_min_samples": 3,
            "tier3_min_samples": 15,
        },
        "thresholds": {
            "tier2_min_match_rate": 0.85,
            "tier3_min_match_rate": 0.95,
        },
        "metrics": metrics,
        "metric_availability": metric_availability,
        "evidence_scope": {
            "syn_phase_transport_available": len(syn_trait_samples) > 0,
            "first_flight_record_lengths_available": True,
            "fixtures_with_first_flight": fixtures_with_first_flight,
            "first_flight_samples_observed": len(first_flight_lengths),
            "syn_samples_observed": len(syn_trait_samples),
        },
        "notes": "Fail-closed extraction: only observed SYN transport metadata contributes to SYN-phase metrics. When SYN evidence is missing, SYN-phase metrics remain explicitly unavailable.",
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract TCP transport coherence metrics from imported ClientHello fixtures."
    )
    parser.add_argument("--repo-root", default=str(REPO_ROOT), help="Repository root path")
    parser.add_argument("--now-utc", default=dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"), 
                       help="Deterministic UTC timestamp (RFC3339 Z)")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="Output JSON file path")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = pathlib.Path(args.repo_root).resolve()
    
    observations = extract_transport_metrics(args.now_utc, repo_root=repo_root)
    
    output_path = pathlib.Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(observations, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    
    print(f"Wrote metrics to {output_path}", file=sys.stderr)
    print(f"Metrics: {json.dumps(observations['metrics'], indent=2)}", file=sys.stderr)
    
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
