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
transport metadata. Therefore, this extractor only computes first-flight TLS
record segmentation metrics from observed data and emits 0.0 for unavailable
transport metrics.
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
    for entry_data in fixtures:
        fixture = entry_data["fixture"]
        lengths = _collect_first_flight_lengths(fixture)
        if lengths:
            fixtures_with_first_flight += 1
            first_flight_lengths.extend(lengths)

    metrics = {
        # Fail closed: no SYN-phase evidence exists in imported fixtures.
        "ttl_bucket_match_rate": 0.0,
        "syn_option_order_class_match_rate": 0.0,
        "mss_window_scale_bucket_match_rate": 0.0,
        "first_flight_segmentation_signature_match_rate": _compute_first_flight_segmentation_rate(first_flight_lengths),
    }

    return {
        "schema_version": 1,
        "generated_at_utc": now_utc,
        "source": str(IMPORTED_MANIFEST_RELATIVE_PATH.as_posix()),
        "sample_count": len(fixtures),
        "method": "Observed first-flight record-length extraction from imported ClientHello fixtures; unavailable SYN-phase metrics are fail-closed to 0.0",
        "power_policy": {
            "tier2_min_samples": 3,
            "tier3_min_samples": 15,
        },
        "thresholds": {
            "tier2_min_match_rate": 0.85,
            "tier3_min_match_rate": 0.95,
        },
        "metrics": metrics,
        "evidence_scope": {
            "syn_phase_transport_available": False,
            "first_flight_record_lengths_available": True,
            "fixtures_with_first_flight": fixtures_with_first_flight,
            "first_flight_samples_observed": len(first_flight_lengths),
        },
        "notes": "Fail-closed extraction: imported fixtures do not carry SYN/TTL/MSS/window-scale evidence, so only first-flight record-length segmentation is scored from observed fixture samples.",
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
