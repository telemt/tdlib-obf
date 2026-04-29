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
    fixture_id: str,
) -> None:
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
        "fixture_family_id": profile_id,
        "samples": [
            {
                "fixture_id": fixture_id,
                "cipher_suites": ["0x1301"],
                "supported_groups": ["0x001D"],
                "key_share_entries": [{"group": "0x001D"}],
                "non_grease_extensions_without_padding": ["0x000D", "0x002B"],
                "alpn_protocols": ["h2"],
                "extensions": [],
                "ech": None,
            }
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


class GenerateImportedFixtureRegistryAdversarialTest(unittest.TestCase):
    def test_rejects_duplicate_fixture_id_across_profiles(self) -> None:
        from generate_imported_fixture_registry import refresh_imported_candidate_corpus

        with tempfile.TemporaryDirectory() as temp_dir:
            base = pathlib.Path(temp_dir)
            clienthello_root = base / "imported" / "clienthello"
            serverhello_root = base / "imported" / "serverhello"
            manifest_path = base / "imported" / "import_manifest.json"
            registry_path = base / "profiles_imported.json"

            capture_a = base / "captures" / "a.pcapng"
            capture_b = base / "captures" / "b.pcapng"
            capture_a.parent.mkdir(parents=True, exist_ok=True)
            capture_a.write_text("a\n", encoding="utf-8")
            capture_b.write_text("b\n", encoding="utf-8")

            duplicate_fixture_id = "collision:frame1"
            write_clienthello_artifact(
                clienthello_root / "windows" / "a.clienthello.json",
                profile_id="chrome146_windows_a",
                source_path=capture_a,
                fixture_id=duplicate_fixture_id,
            )
            write_clienthello_artifact(
                clienthello_root / "windows" / "b.clienthello.json",
                profile_id="chrome146_windows_b",
                source_path=capture_b,
                fixture_id=duplicate_fixture_id,
            )

            manifest_payload = {
                "version": "imported-capture-corpus-v1",
                "entries": [
                    {
                        "capture_path": str(capture_a.resolve()),
                        "profile_id": "chrome146_windows_a",
                        "browser_alias": "chrome",
                        "route_mode": "non_ru_egress",
                    },
                    {
                        "capture_path": str(capture_b.resolve()),
                        "profile_id": "chrome146_windows_b",
                        "browser_alias": "chrome",
                        "route_mode": "non_ru_egress",
                    },
                ],
            }
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            manifest_path.write_text(json.dumps(manifest_payload), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "duplicate fixture_id"):
                refresh_imported_candidate_corpus(
                    clienthello_root,
                    serverhello_root,
                    manifest_path,
                    registry_path,
                    "non_ru_egress",
                )

    def test_rejects_duplicate_fixture_id_within_same_artifact(self) -> None:
        from generate_imported_fixture_registry import refresh_imported_candidate_corpus

        with tempfile.TemporaryDirectory() as temp_dir:
            base = pathlib.Path(temp_dir)
            clienthello_root = base / "imported" / "clienthello"
            serverhello_root = base / "imported" / "serverhello"
            manifest_path = base / "imported" / "import_manifest.json"
            registry_path = base / "profiles_imported.json"

            capture = base / "captures" / "same.pcapng"
            capture.parent.mkdir(parents=True, exist_ok=True)
            capture.write_text("same\n", encoding="utf-8")

            fixture_id = "same-collision:frame1"
            payload = {
                "artifact_type": "tls_clienthello_fixtures",
                "parser_version": "tls-clienthello-parser-v1",
                "profile_id": "chrome146_windows_same",
                "route_mode": "non_ru_egress",
                "scenario_id": "chrome146_windows_same-scenario",
                "source_path": str(capture.resolve()),
                "source_sha256": "a" * 64,
                "source_kind": "browser_capture",
                "device_class": "desktop",
                "os_family": "windows",
                "transport": "tcp",
                "fixture_family_id": "chrome146_windows_same",
                "samples": [
                    {
                        "fixture_id": fixture_id,
                        "cipher_suites": ["0x1301"],
                        "supported_groups": ["0x001D"],
                        "key_share_entries": [{"group": "0x001D"}],
                        "non_grease_extensions_without_padding": ["0x000D", "0x002B"],
                        "alpn_protocols": ["h2"],
                        "extensions": [],
                        "ech": None,
                    },
                    {
                        "fixture_id": fixture_id,
                        "cipher_suites": ["0x1301"],
                        "supported_groups": ["0x001D"],
                        "key_share_entries": [{"group": "0x001D"}],
                        "non_grease_extensions_without_padding": ["0x000D", "0x002B"],
                        "alpn_protocols": ["h2"],
                        "extensions": [],
                        "ech": None,
                    },
                ],
            }
            target = clienthello_root / "windows" / "same.clienthello.json"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(payload), encoding="utf-8")

            manifest_payload = {
                "version": "imported-capture-corpus-v1",
                "entries": [
                    {
                        "capture_path": str(capture.resolve()),
                        "profile_id": "chrome146_windows_same",
                        "browser_alias": "chrome",
                        "route_mode": "non_ru_egress",
                    }
                ],
            }
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            manifest_path.write_text(json.dumps(manifest_payload), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "duplicate fixture_id"):
                refresh_imported_candidate_corpus(
                    clienthello_root,
                    serverhello_root,
                    manifest_path,
                    registry_path,
                    "non_ru_egress",
                )


if __name__ == "__main__":
    unittest.main()
