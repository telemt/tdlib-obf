# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs

from __future__ import annotations

import json
import pathlib
import tempfile
import unittest

from common_tls import read_sha256
from generate_imported_fixture_registry import refresh_imported_candidate_corpus
from run_corpus_smoke import run_corpus_smoke


def write_imported_clienthello_artifact(
    path: pathlib.Path,
    *,
    profile_id: str,
    source_path: pathlib.Path,
    route_mode: str,
) -> None:
    source_sha256 = read_sha256(source_path)
    payload = {
        "artifact_type": "tls_clienthello_fixtures",
        "parser_version": "tls-clienthello-parser-v1",
        "profile_id": profile_id,
        "route_mode": route_mode,
        "scenario_id": f"{profile_id}-scenario",
        "source_path": str(source_path.resolve()),
        "source_sha256": source_sha256,
        "source_kind": "browser_capture",
        "device_class": "desktop",
        "os_family": "windows",
        "transport": "tcp",
        "fixture_family_id": profile_id,
        "samples": [
            {
                "fixture_id": f"{profile_id}:frame1",
                "fixture_family_id": profile_id,
                "cipher_suites": ["0x1301"],
                "supported_groups": ["0x001D"],
                "key_share_entries": [{"group": "0x001D"}],
                "non_grease_extensions_without_padding": ["0x000D", "0x002B"],
                "alpn_protocols": ["h2"],
                "extensions": [
                    {"type": "0x002B", "body_hex": "00020304"},
                    {"type": "0xFE0D", "body_hex": "00"},
                ],
                "ech": {"payload_length": 208},
            },
            {
                "fixture_id": f"{profile_id}:frame2",
                "fixture_family_id": profile_id,
                "cipher_suites": ["0x1301"],
                "supported_groups": ["0x001D"],
                "key_share_entries": [{"group": "0x001D"}],
                "non_grease_extensions_without_padding": ["0x000D", "0x002B"],
                "alpn_protocols": ["h2"],
                "extensions": [{"type": "0x002B", "body_hex": "00020304"}],
                "ech": None,
            },
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def write_imported_serverhello_artifact(
    path: pathlib.Path,
    *,
    profile_id: str,
    source_path: pathlib.Path,
    route_mode: str,
) -> None:
    source_sha256 = read_sha256(source_path)
    payload = {
        "artifact_type": "tls_serverhello_fixtures",
        "parser_version": "tls-serverhello-parser-v1",
        "route_mode": route_mode,
        "scenario_id": f"{profile_id}-serverhello",
        "source_path": str(source_path.resolve()),
        "source_sha256": source_sha256,
        "source_kind": "browser_capture",
        "transport": "tcp",
        "capture_provenance": {
            "client_profile_id": profile_id,
        },
        "samples": [
            {
                "fixture_id": f"{profile_id}:frame8",
                "family": profile_id,
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


class ImportedCorpusRouteEchServerhelloIntegrationTest(unittest.TestCase):
    def test_imported_registry_binds_route_ech_and_serverhello_pairing_end_to_end(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = pathlib.Path(temp_dir)
            clienthello_root = base / "fixtures" / "imported" / "clienthello"
            serverhello_root = base / "fixtures" / "imported" / "serverhello"
            manifest_path = base / "fixtures" / "imported" / "import_manifest.json"
            registry_path = base / "profiles_imported.json"

            capture = base / "captures" / "chrome.pcapng"
            capture.parent.mkdir(parents=True, exist_ok=True)
            capture.write_text("capture\n", encoding="utf-8")

            profile_id = "chrome146_windows_test"
            write_imported_clienthello_artifact(
                clienthello_root / "windows" / "chrome.clienthello.json",
                profile_id=profile_id,
                source_path=capture,
                route_mode="unknown",
            )
            write_imported_serverhello_artifact(
                serverhello_root / "windows" / "chrome.serverhello.json",
                profile_id=profile_id,
                source_path=capture,
                route_mode="unknown",
            )

            manifest_payload = {
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
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            manifest_path.write_text(json.dumps(manifest_payload), encoding="utf-8")

            generated_registry = refresh_imported_candidate_corpus(
                clienthello_root,
                serverhello_root,
                manifest_path,
                registry_path,
                "non_ru_egress",
            )
            self.assertEqual(
                {"allow_present": True, "allow_absent": True},
                generated_registry["profiles"][profile_id]["ech_type"],
            )

            non_ru_report = run_corpus_smoke(
                registry_path,
                clienthello_root,
                server_hello_fixtures_root=serverhello_root,
            )
            self.assertTrue(non_ru_report["ok"])

            refresh_imported_candidate_corpus(
                clienthello_root,
                serverhello_root,
                manifest_path,
                registry_path,
                "ru_egress",
            )
            ru_report = run_corpus_smoke(
                registry_path,
                clienthello_root,
                server_hello_fixtures_root=serverhello_root,
            )
            self.assertFalse(ru_report["ok"])
            self.assertTrue(
                any("ECH route policy" in failure for failure in ru_report["failures"])
            )


if __name__ == "__main__":
    unittest.main()
