#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs
"""
Refresh policy-derived fields in profiles_validation.json from actual reviewed
clienthello artifact files, without touching curated provenance or trust fields.

Fields re-derived (from actual sample data, same logic as generate_imported_fixture_registry.py):
  - include_fixture_ids  (all fixture IDs found in the registry that match sample fixture_ids)
  - alps_type            (derived from all samples in the artifact)
  - pq_group             (derived from all samples in the artifact)
  - ech_type             (derived from all samples in the artifact)
  - extension_order_policy  (ChromeShuffleAnchored unless profile_id starts with 'safari')

Fields PRESERVED unchanged:
  - trust_tier (per fixture)
  - release_gating (per profile)
  - allowed_tags (per profile)
  - fingerprint_policy (per profile)
  - contamination_guard, source, server_hello_matrix, version (registry-level)

Side effect -- adds missing fixture entries:
  For each sample whose fixture_id is absent from the registry fixtures section, a new fixture
  entry is added using build_fixture_entry(), inheriting trust_tier from an existing fixture
  for the same source_sha256 (defaults to 'candidate' if none found).
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any

THIS_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = THIS_DIR.parent.parent

if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from common_tls import ClientHello, load_clienthello_artifact  # noqa: E402
from generate_imported_fixture_registry import (  # noqa: E402
    build_fixture_entry,
    derive_alps_policy,
    derive_ech_policy,
    derive_pq_policy,
)

DEFAULT_REGISTRY_PATH = THIS_DIR / "profiles_validation.json"
DEFAULT_CLIENTHELLO_ROOT = THIS_DIR / "fixtures" / "clienthello"


def derive_extension_order_policy(profile_id: str) -> str:
    """Reviewed lane uses FixedFromFixture only for Safari; everything else uses ChromeShuffleAnchored."""
    return "FixedFromFixture" if profile_id.startswith("safari") else "ChromeShuffleAnchored"


def discover_artifact_paths(root: pathlib.Path) -> list[pathlib.Path]:
    return sorted(path for path in root.rglob("*.clienthello.json") if path.is_file())


def ensure_fixture_entries(
    samples: list[ClientHello],
    registry_fixtures: dict[str, dict[str, Any]],
) -> None:
    """
    Add fixture entries for any sample whose fixture_id is not yet in registry_fixtures.
    Uses build_fixture_entry() and inherits trust_tier from an existing fixture for the
    same source_sha256 (defaults to 'candidate' if none found).
    """
    sha256_to_trust_tier: dict[str, str] = {}
    for fixture in registry_fixtures.values():
        sha256 = (fixture.get("source_sha256") or "").lower()
        tier = fixture.get("trust_tier", "candidate")
        if sha256 and sha256 not in sha256_to_trust_tier:
            sha256_to_trust_tier[sha256] = tier

    for sample in samples:
        fid = sample.metadata.fixture_id
        if not fid or fid in registry_fixtures:
            continue
        entry = build_fixture_entry(sample)
        src_sha256 = sample.metadata.source_sha256.lower() if sample.metadata.source_sha256 else ""
        inherited_tier = sha256_to_trust_tier.get(src_sha256, "candidate")
        entry["trust_tier"] = inherited_tier
        registry_fixtures[fid] = entry


def collect_fixture_ids_from_samples(
    registry_fixtures: dict[str, dict[str, Any]],
    samples: list[ClientHello],
) -> list[str]:
    """
    Collect all fixture IDs in the registry that correspond to samples in this artifact.
    Matching is done by sample.metadata.fixture_id (direct lookup) -- reliable even when
    the registry fixture's family field doesn't match the profile name (legacy alias
    profiles such as chrome144_linux_desktop vs chromium_44cd_mlkem_linux_desktop).
    """
    matching_ids: list[str] = []
    seen: set[str] = set()
    for sample in samples:
        fid = sample.metadata.fixture_id
        if fid and fid not in seen and fid in registry_fixtures:
            matching_ids.append(fid)
            seen.add(fid)
    return sorted(matching_ids)


def refresh_profile(
    profile_name: str,
    existing_profile: dict[str, Any],
    samples: list[ClientHello],
    registry_fixtures: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """
    Return an updated profile dict, re-deriving policy fields from sample data.
    Preserves release_gating, allowed_tags, and fingerprint_policy unchanged.
    """
    updated = dict(existing_profile)

    include_ids = collect_fixture_ids_from_samples(registry_fixtures, samples)
    updated["include_fixture_ids"] = include_ids

    # If no fixture IDs found (code-only profiles with no network capture), clear
    # extension_order_policy so the check passes trivially rather than false-failing.
    if not include_ids:
        updated["extension_order_policy"] = None
        return updated

    updated["alps_type"] = derive_alps_policy(samples)
    updated["pq_group"] = derive_pq_policy(samples)
    updated["ech_type"] = derive_ech_policy(samples)
    updated["extension_order_policy"] = derive_extension_order_policy(profile_name)

    return updated


def refresh_reviewed_profiles(
    registry_path: pathlib.Path,
    clienthello_root: pathlib.Path,
    *,
    dry_run: bool = False,
) -> dict[str, list[str]]:
    """
    Refresh policies for all profiles in registry_path using artifact data from clienthello_root.
    Returns a dict with 'updated', 'skipped', and 'errors' lists of profile names.
    """
    with registry_path.open("r", encoding="utf-8") as fh:
        registry: dict[str, Any] = json.load(fh)

    if not isinstance(registry, dict):
        raise ValueError(f"registry must be a JSON object: {registry_path}")

    existing_profiles: dict[str, Any] = registry.get("profiles", {})
    registry_fixtures: dict[str, Any] = registry.get("fixtures", {})

    if not isinstance(existing_profiles, dict):
        raise ValueError("registry must contain a 'profiles' object")

    artifact_paths = discover_artifact_paths(clienthello_root)
    artifact_by_profile: dict[str, pathlib.Path] = {}
    for path in artifact_paths:
        profile_id = path.stem.replace(".clienthello", "")
        artifact_by_profile[profile_id] = path

    updated_list: list[str] = []
    skipped: list[str] = []
    errors: list[str] = []
    refreshed_profiles: dict[str, dict[str, Any]] = {}

    for profile_name, existing_profile in existing_profiles.items():
        artifact_path = artifact_by_profile.get(profile_name)
        if artifact_path is None:
            skipped.append(profile_name)
            refreshed_profiles[profile_name] = existing_profile
            continue

        try:
            samples = load_clienthello_artifact(artifact_path)
        except Exception as exc:
            errors.append(f"{profile_name}: {exc}")
            refreshed_profiles[profile_name] = existing_profile
            continue

        if not samples:
            skipped.append(profile_name)
            refreshed_profiles[profile_name] = existing_profile
            continue

        # Ensure all sample frames have fixture entries in the registry before deriving IDs
        ensure_fixture_entries(samples, registry_fixtures)

        new_profile = refresh_profile(
            profile_name, existing_profile, samples, registry_fixtures
        )
        refreshed_profiles[profile_name] = new_profile

        if new_profile != existing_profile:
            updated_list.append(profile_name)

    registry["profiles"] = refreshed_profiles

    if not dry_run:
        registry_path.write_text(
            json.dumps(registry, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    return {"updated": updated_list, "skipped": skipped, "errors": errors}


def main() -> None:
    parser = argparse.ArgumentParser(description="Refresh reviewed corpus profile policy fields.")
    parser.add_argument(
        "--registry",
        default=str(DEFAULT_REGISTRY_PATH),
        help="Path to profiles_validation.json",
    )
    parser.add_argument(
        "--fixtures-root",
        default=str(DEFAULT_CLIENTHELLO_ROOT),
        help="Root directory containing reviewed clienthello artifact JSON files",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be changed without writing",
    )
    args = parser.parse_args()

    registry_path = pathlib.Path(args.registry).resolve()
    clienthello_root = pathlib.Path(args.fixtures_root).resolve()

    if not registry_path.exists():
        raise SystemExit(f"registry not found: {registry_path}")
    if not clienthello_root.exists():
        raise SystemExit(f"fixtures root not found: {clienthello_root}")

    result = refresh_reviewed_profiles(
        registry_path,
        clienthello_root,
        dry_run=args.dry_run,
    )

    status = "DRY RUN -- no changes written" if args.dry_run else "Written"
    print(f"{status}: {len(result['updated'])} profiles updated, "
          f"{len(result['skipped'])} skipped (no artifact), "
          f"{len(result['errors'])} errors")

    if result["updated"]:
        print("\nUpdated profiles:")
        for name in sorted(result["updated"]):
            print(f"  {name}")

    if result["skipped"]:
        print("\nSkipped (no artifact file):")
        for name in sorted(result["skipped"]):
            print(f"  {name}")

    if result["errors"]:
        print("\nErrors:")
        for msg in result["errors"]:
            print(f"  {msg}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
