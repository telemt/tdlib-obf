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

from common_tls import (
    ClientHello,
    ServerHello,
    has_extension,
    load_clienthello_artifact,
    load_server_hello_artifact,
)

THIS_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = THIS_DIR.parent.parent
DEFAULT_CLIENTHELLO_ROOT = THIS_DIR / "fixtures" / "imported" / "clienthello"
DEFAULT_SERVERHELLO_ROOT = THIS_DIR / "fixtures" / "imported" / "serverhello"
DEFAULT_MANIFEST_PATH = THIS_DIR / "fixtures" / "imported" / "import_manifest.json"
DEFAULT_REGISTRY_PATH = THIS_DIR / "profiles_imported.json"
ALPS_EXTENSION_TYPES = {0x44CD, 0x4469}


def repo_relative(path: pathlib.Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(path.resolve())


def load_json(path: pathlib.Path) -> Any:
    with path.open("r", encoding="utf-8") as infile:
        return json.load(infile)


def write_json(path: pathlib.Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def normalize_artifact_route_mode(path: pathlib.Path, route_mode: str) -> None:
    payload = load_json(path)
    if not isinstance(payload, dict):
        raise ValueError(f"artifact must be a JSON object: {path}")
    if payload.get("route_mode") == route_mode:
        return
    payload["route_mode"] = route_mode
    write_json(path, payload)


def load_manifest(path: pathlib.Path) -> dict[str, Any]:
    payload = load_json(path)
    if not isinstance(payload, dict):
        raise ValueError(f"manifest must be a JSON object: {path}")
    entries = payload.get("entries")
    if not isinstance(entries, list):
        raise ValueError(f"manifest entries must be a list: {path}")
    return payload


def manifest_entry_index(manifest_payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for entry in manifest_payload.get("entries", []):
        if not isinstance(entry, dict):
            continue
        capture_path = entry.get("capture_path")
        if isinstance(capture_path, str) and capture_path:
            index[capture_path] = entry
    return index


def normalize_manifest_route_mode(
    manifest_payload: dict[str, Any], route_mode: str
) -> None:
    for entry in manifest_payload.get("entries", []):
        if isinstance(entry, dict):
            entry["route_mode"] = route_mode


def parse_capture_browser_alias(
    profile_id: str, manifest_entry: dict[str, Any] | None
) -> str:
    if isinstance(manifest_entry, dict):
        browser_alias = manifest_entry.get("browser_alias")
        if isinstance(browser_alias, str) and browser_alias:
            return browser_alias
    return "safari" if profile_id.startswith("safari") else profile_id.split("_")[0]


def derive_extension_order_policy(browser_alias: str) -> str:
    return "FixedFromFixture" if browser_alias == "safari" else "ChromeShuffleAnchored"


def _encode_u16(value: int) -> str:
    return f"0x{value:04X}"


def derive_ech_policy(samples: list[ClientHello]) -> Any:
    presence = {has_extension(sample, 0xFE0D) for sample in samples}
    if presence == {False}:
        return None
    if presence == {True}:
        return "0xFE0D"
    return {
        "allow_present": True,
        "allow_absent": True,
    }


def derive_optional_u16_policy(observed_sets: list[set[int]], *, key: str) -> Any:
    allowed_values = sorted({value for observed in observed_sets for value in observed})
    allow_absent = any(not observed for observed in observed_sets)
    if not allowed_values:
        return None
    if len(allowed_values) == 1 and not allow_absent:
        return _encode_u16(allowed_values[0])
    return {
        key: [_encode_u16(value) for value in allowed_values],
        "allow_absent": allow_absent,
    }


def derive_alps_policy(samples: list[ClientHello]) -> Any:
    observed_sets = [
        {
            extension.type
            for extension in sample.extensions
            if extension.type in ALPS_EXTENSION_TYPES
        }
        for sample in samples
    ]
    return derive_optional_u16_policy(observed_sets, key="allowed_types")


def derive_pq_policy(samples: list[ClientHello]) -> Any:
    observed_sets: list[set[int]] = []
    for sample in samples:
        observed_sets.append(
            {
                group
                for group in sample.supported_groups
                if group in sample.key_share_groups
                and group >= 0x1000
                and (group & 0x0F0F) != 0x0A0A
            }
        )
    return derive_optional_u16_policy(observed_sets, key="allowed_groups")


def build_fixture_entry(sample: ClientHello) -> dict[str, Any]:
    return {
        "source_path": sample.metadata.source_path,
        "source_sha256": sample.metadata.source_sha256,
        "source_kind": sample.metadata.source_kind,
        "trust_tier": "candidate",
        "family": sample.profile,
        "transport": sample.metadata.transport,
        "platform_class": sample.metadata.device_class,
        "os_family": sample.metadata.os_family,
        "tls_gen": sample.metadata.tls_gen,
        "non_grease_extensions_without_padding": [
            _encode_u16(value) for value in sample.non_grease_extensions_without_padding
        ],
        "supported_groups": [_encode_u16(value) for value in sample.supported_groups],
        "key_share_groups": [_encode_u16(value) for value in sample.key_share_groups],
        "route_mode": sample.metadata.route_mode,
    }


def build_profile_entry(
    samples: list[ClientHello], browser_alias: str
) -> dict[str, Any]:
    first = samples[0]
    return {
        "release_gating": False,
        "include_fixture_ids": [
            sample.metadata.fixture_id
            for sample in samples
            if sample.metadata.fixture_id
        ],
        "allowed_tags": {
            "source_kind": sorted(
                {
                    sample.metadata.source_kind
                    for sample in samples
                    if sample.metadata.source_kind
                }
            ),
            "family": [first.profile],
            "platform_class": sorted(
                {
                    sample.metadata.device_class
                    for sample in samples
                    if sample.metadata.device_class
                }
            ),
            "os_family": sorted(
                {
                    sample.metadata.os_family
                    for sample in samples
                    if sample.metadata.os_family
                }
            ),
            "tls_gen": sorted(
                {
                    sample.metadata.tls_gen
                    for sample in samples
                    if sample.metadata.tls_gen
                }
            ),
            "transport": sorted(
                {
                    sample.metadata.transport
                    for sample in samples
                    if sample.metadata.transport
                }
            ),
        },
        "ech_type": derive_ech_policy(samples),
        "pq_group": derive_pq_policy(samples),
        "alps_type": derive_alps_policy(samples),
        "extension_order_policy": derive_extension_order_policy(browser_alias),
        "fingerprint_policy": {
            "allow_exact_ja3_pin": False,
            "allow_exact_ja4_pin": False,
            "require_structural_match": True,
            "require_anti_telegram_ja3": True,
            "require_noncollapsed_randomized_hashes": False,
        },
    }


def validate_clienthello_profile_family(
    samples: list[ClientHello], profile_id: str
) -> str:
    observed_families = {
        sample.metadata.fixture_family_id.strip()
        for sample in samples
        if sample.metadata.fixture_family_id.strip()
    }
    if not observed_families:
        raise ValueError(f"profile '{profile_id}' is missing fixture_family_id")
    if len(observed_families) != 1:
        raise ValueError(
            f"profile '{profile_id}' contains mixed fixture_family_id values: {sorted(observed_families)}"
        )
    family = next(iter(observed_families))
    if family != profile_id:
        raise ValueError(
            f"profile '{profile_id}' fixture_family_id must match profile_id; got '{family}'"
        )
    return family


def validate_serverhello_profile_family(
    samples: list[ServerHello], known_profiles: set[str]
) -> str:
    observed_families = {
        sample.metadata.fixture_family_id.strip()
        for sample in samples
        if sample.metadata.fixture_family_id.strip()
    }
    if not observed_families:
        raise ValueError("server hello artifact is missing fixture family")
    if len(observed_families) != 1:
        raise ValueError(
            f"server hello artifact contains mixed fixture_family_id values: {sorted(observed_families)}"
        )
    family = next(iter(observed_families))

    observed_client_profiles = {
        sample.metadata.client_profile_id.strip()
        for sample in samples
        if sample.metadata.client_profile_id.strip()
    }
    if len(observed_client_profiles) > 1:
        raise ValueError(
            "server hello artifact contains mixed capture_provenance.client_profile_id values: "
            f"{sorted(observed_client_profiles)}"
        )
    if observed_client_profiles:
        client_profile_id = next(iter(observed_client_profiles))
        if family != client_profile_id:
            raise ValueError(
                "server hello family '"
                f"{family}' does not match capture_provenance.client_profile_id '{client_profile_id}'"
            )
    if family not in known_profiles:
        raise ValueError(
            f"server hello family '{family}' does not match any imported client profile"
        )
    return family


def build_server_hello_policy(samples: list[ServerHello]) -> dict[str, Any]:
    first = samples[0]
    allowed_tuples = []
    seen_tuples: set[tuple[int, int, tuple[int, ...]]] = set()
    for sample in samples:
        key = (sample.selected_version, sample.cipher_suite, tuple(sample.extensions))
        if key in seen_tuples:
            continue
        seen_tuples.add(key)
        allowed_tuples.append(
            {
                "selected_version": _encode_u16(sample.selected_version),
                "cipher_suite": _encode_u16(sample.cipher_suite),
                "extensions": [_encode_u16(value) for value in sample.extensions],
            }
        )

    allowed_layouts: list[list[int]] = []
    seen_layouts: set[tuple[int, ...]] = set()
    for sample in samples:
        layout = tuple(sample.record_layout_signature)
        if layout in seen_layouts:
            continue
        seen_layouts.add(layout)
        allowed_layouts.append(list(layout))

    return {
        "parser_version": first.metadata.parser_version,
        "allowed_tuples": allowed_tuples,
        "allowed_layout_signatures": allowed_layouts,
    }


def discover_artifact_paths(root: pathlib.Path) -> list[pathlib.Path]:
    return sorted(path for path in root.rglob("*.json") if path.is_file())


def add_fixture_entries(
    samples: list[ClientHello],
    fixtures: dict[str, dict[str, Any]],
    fixture_sources: dict[str, str],
) -> None:
    for sample in samples:
        if not sample.metadata.fixture_id:
            continue
        fixture_id = sample.metadata.fixture_id
        source_path = sample.metadata.source_path
        existing_source = fixture_sources.get(fixture_id)
        if existing_source is not None:
            raise ValueError(
                f"duplicate fixture_id '{fixture_id}' declared by both "
                f"'{existing_source}' and '{source_path}'"
            )
        fixture_sources[fixture_id] = source_path
        fixtures[fixture_id] = build_fixture_entry(sample)


def collect_clienthello_registry_data(
    clienthello_root: pathlib.Path,
    route_mode: str,
    manifest_index: dict[str, dict[str, Any]],
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    fixtures: dict[str, dict[str, Any]] = {}
    fixture_sources: dict[str, str] = {}
    profile_samples: dict[str, list[ClientHello]] = {}
    profile_browser_alias: dict[str, str] = {}

    for artifact_path in discover_artifact_paths(clienthello_root):
        normalize_artifact_route_mode(artifact_path, route_mode)
        samples = load_clienthello_artifact(artifact_path)
        if not samples:
            continue

        profile_id = samples[0].profile
        validate_clienthello_profile_family(samples, profile_id)
        capture_key = repo_relative(pathlib.Path(samples[0].metadata.source_path))
        manifest_entry = manifest_index.get(capture_key)
        browser_alias = parse_capture_browser_alias(profile_id, manifest_entry)
        if browser_alias == "unknown_browser":
            continue

        add_fixture_entries(samples, fixtures, fixture_sources)
        existing_alias = profile_browser_alias.get(profile_id)
        if existing_alias is None:
            profile_browser_alias[profile_id] = browser_alias
        elif existing_alias != browser_alias:
            raise ValueError(
                f"profile '{profile_id}' has conflicting browser aliases: "
                f"'{existing_alias}' vs '{browser_alias}'"
            )

        profile_samples.setdefault(profile_id, []).extend(samples)

    profiles: dict[str, dict[str, Any]] = {
        profile_id: build_profile_entry(samples, profile_browser_alias[profile_id])
        for profile_id, samples in profile_samples.items()
    }

    return fixtures, profiles


def collect_server_hello_matrix(
    serverhello_root: pathlib.Path,
    route_mode: str,
    profiles: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    server_hello_matrix: dict[str, Any] = {}

    for artifact_path in discover_artifact_paths(serverhello_root):
        normalize_artifact_route_mode(artifact_path, route_mode)
        samples = load_server_hello_artifact(artifact_path)
        if not samples:
            continue

        family = validate_serverhello_profile_family(samples, set(profiles))
        server_hello_matrix[family] = build_server_hello_policy(samples)

    return server_hello_matrix


def refresh_imported_candidate_corpus(
    clienthello_root: pathlib.Path,
    serverhello_root: pathlib.Path,
    manifest_path: pathlib.Path,
    registry_path: pathlib.Path,
    route_mode: str,
) -> dict[str, Any]:
    manifest_payload = load_manifest(manifest_path)
    normalize_manifest_route_mode(manifest_payload, route_mode)
    manifest_index = manifest_entry_index(manifest_payload)

    fixtures, profiles = collect_clienthello_registry_data(
        clienthello_root, route_mode, manifest_index
    )
    server_hello_matrix = collect_server_hello_matrix(
        serverhello_root, route_mode, profiles
    )

    write_json(manifest_path, manifest_payload)
    registry = {
        "contamination_guard": {
            "fail_on_missing_required_tag": True,
            "allow_mixed_source_kind_per_profile": False,
            "allow_mixed_family_per_profile": False,
            "allow_advisory_code_sample_per_profile": False,
        },
        "fixtures": fixtures,
        "profiles": profiles,
        "server_hello_matrix": server_hello_matrix,
    }
    write_json(registry_path, registry)
    return registry


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Normalize imported candidate fixture metadata and generate a dedicated imported-corpus registry."
    )
    parser.add_argument(
        "--clienthello-root",
        default=str(DEFAULT_CLIENTHELLO_ROOT),
        help="Imported ClientHello artifact root",
    )
    parser.add_argument(
        "--serverhello-root",
        default=str(DEFAULT_SERVERHELLO_ROOT),
        help="Imported ServerHello artifact root",
    )
    parser.add_argument(
        "--manifest",
        default=str(DEFAULT_MANIFEST_PATH),
        help="Imported manifest JSON path",
    )
    parser.add_argument(
        "--out", default=str(DEFAULT_REGISTRY_PATH), help="Output registry JSON path"
    )
    parser.add_argument(
        "--route-mode",
        default="non_ru_egress",
        help="Route mode to stamp onto imported artifacts and manifest entries",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    refresh_imported_candidate_corpus(
        pathlib.Path(args.clienthello_root).resolve(),
        pathlib.Path(args.serverhello_root).resolve(),
        pathlib.Path(args.manifest).resolve(),
        pathlib.Path(args.out).resolve(),
        args.route_mode,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
