# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs

import json
import pathlib
import sys
import tempfile
import unittest

THIS_DIR = pathlib.Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))


def write_clienthello_artifact(
    path: pathlib.Path,
    *,
    profile_id: str,
    source_path: pathlib.Path,
    fixture_family_ids: list[str],
) -> None:
    samples = []
    for index, fixture_family_id in enumerate(fixture_family_ids, start=1):
        samples.append(
            {
                "fixture_id": f"{profile_id}:frame{index}",
                "fixture_family_id": fixture_family_id,
                "cipher_suites": ["0x1301"],
                "supported_groups": ["0x001D"],
                "key_share_entries": [{"group": "0x001D"}],
                "non_grease_extensions_without_padding": ["0x000D", "0x002B"],
                "alpn_protocols": ["h2"],
                "extensions": [],
                "ech": None,
            }
        )
    payload = {
        "artifact_type": "tls_clienthello_fixtures",
        "parser_version": "tls-clienthello-parser-v1",
        "profile_id": profile_id,
        "route_mode": "non_ru_egress",
        "scenario_id": f"{profile_id}-scenario",
        "source_path": str(source_path.resolve()),
        "source_sha256": "a" * 64,
        "source_kind": "browser_capture",
        "device_class": "desktop",
        "os_family": "windows",
        "transport": "tcp",
        "fixture_family_id": fixture_family_ids[0],
        "samples": samples,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def write_manifest(
    path: pathlib.Path, capture_path: pathlib.Path, profile_id: str
) -> None:
    payload = {
        "version": "imported-capture-corpus-v1",
        "entries": [
            {
                "capture_path": str(capture_path.resolve()),
                "profile_id": profile_id,
                "browser_alias": "chrome",
                "route_mode": "non_ru_egress",
            }
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


class GenerateImportedFixtureRegistryFamilyContractTest(unittest.TestCase):
    def test_rejects_profile_with_mixed_fixture_families(self) -> None:
        from generate_imported_fixture_registry import refresh_imported_candidate_corpus

        with tempfile.TemporaryDirectory() as temp_dir:
            base = pathlib.Path(temp_dir)
            clienthello_root = base / "imported" / "clienthello"
            serverhello_root = base / "imported" / "serverhello"
            manifest_path = base / "imported" / "import_manifest.json"
            registry_path = base / "profiles_imported.json"

            capture = base / "captures" / "chrome.pcapng"
            capture.parent.mkdir(parents=True, exist_ok=True)
            capture.write_text("capture\n", encoding="utf-8")

            write_clienthello_artifact(
                clienthello_root / "windows" / "chrome.clienthello.json",
                profile_id="chrome146_windows_test",
                source_path=capture,
                fixture_family_ids=["chrome146_windows_test", "chrome146_macos_test"],
            )
            write_manifest(manifest_path, capture, "chrome146_windows_test")

            with self.assertRaisesRegex(ValueError, "mixed fixture_family_id"):
                refresh_imported_candidate_corpus(
                    clienthello_root,
                    serverhello_root,
                    manifest_path,
                    registry_path,
                    "non_ru_egress",
                )


if __name__ == "__main__":
    unittest.main()
