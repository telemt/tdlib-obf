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
    path: pathlib.Path, *, profile_id: str, source_path: pathlib.Path
) -> None:
    payload = {
        "artifact_type": "tls_clienthello_fixtures",
        "parser_version": "tls-clienthello-parser-v1",
        "profile_id": profile_id,
        "route_mode": "unknown",
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
                "fixture_id": f"{profile_id}:frame1",
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


def write_serverhello_artifact(
    path: pathlib.Path,
    *,
    family: str,
    client_profile_id: str,
    source_path: pathlib.Path,
) -> None:
    payload = {
        "artifact_type": "tls_serverhello_fixtures",
        "parser_version": "tls-serverhello-parser-v1",
        "route_mode": "unknown",
        "scenario_id": f"{family}-serverhello",
        "source_path": str(source_path.resolve()),
        "source_sha256": "b" * 64,
        "source_kind": "browser_capture",
        "transport": "tcp",
        "capture_provenance": {"client_profile_id": client_profile_id},
        "samples": [
            {
                "fixture_id": f"{family}:frame8",
                "family": family,
                "selected_version": "0x0304",
                "cipher_suite": "0x1301",
                "extensions": ["0x002b", "0x0033"],
                "record_layout_signature": [22, 20],
                "server_endpoint": {"ip": "142.250.186.46", "port": 443},
            }
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


class GenerateImportedFixtureRegistryFamilyIntegrationTest(unittest.TestCase):
    def test_rejects_serverhello_family_that_does_not_match_client_profile(
        self,
    ) -> None:
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

            profile_id = "chrome146_windows_test"
            write_clienthello_artifact(
                clienthello_root / "windows" / "chrome.clienthello.json",
                profile_id=profile_id,
                source_path=capture,
            )
            write_serverhello_artifact(
                serverhello_root / "windows" / "chrome.serverhello.json",
                family="firefox149_windows_test",
                client_profile_id=profile_id,
                source_path=capture,
            )
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            manifest_path.write_text(
                json.dumps(
                    {
                        "version": "imported-capture-corpus-v1",
                        "entries": [
                            {
                                "capture_path": str(capture.resolve()),
                                "profile_id": profile_id,
                                "browser_alias": "chrome",
                                "route_mode": "unknown",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                ValueError, "server hello family.*does not match"
            ):
                refresh_imported_candidate_corpus(
                    clienthello_root,
                    serverhello_root,
                    manifest_path,
                    registry_path,
                    "non_ru_egress",
                )


if __name__ == "__main__":
    unittest.main()
