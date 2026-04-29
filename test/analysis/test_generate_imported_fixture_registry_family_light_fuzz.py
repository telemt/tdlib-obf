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


class GenerateImportedFixtureRegistryFamilyLightFuzzTest(unittest.TestCase):
    def test_rejects_single_foreign_family_across_mutated_positions(self) -> None:
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
                                "route_mode": "non_ru_egress",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            for foreign_index in range(16):
                sample_count = 8 + foreign_index
                foreign_slot = (foreign_index * 7 + 3) % sample_count
                samples = []
                for index in range(sample_count):
                    family = (
                        profile_id
                        if index != foreign_slot
                        else f"foreign_family_{foreign_index}"
                    )
                    samples.append(
                        {
                            "fixture_id": f"{profile_id}:frame{index + 1}",
                            "fixture_family_id": family,
                            "cipher_suites": ["0x1301"],
                            "supported_groups": ["0x001D"],
                            "key_share_entries": [{"group": "0x001D"}],
                            "non_grease_extensions_without_padding": [
                                "0x000D",
                                "0x002B",
                            ],
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
                    "source_path": str(capture.resolve()),
                    "source_sha256": "a" * 64,
                    "source_kind": "browser_capture",
                    "device_class": "desktop",
                    "os_family": "windows",
                    "transport": "tcp",
                    "fixture_family_id": profile_id,
                    "samples": samples,
                }
                artifact_path = clienthello_root / "windows" / "chrome.clienthello.json"
                artifact_path.parent.mkdir(parents=True, exist_ok=True)
                artifact_path.write_text(json.dumps(payload), encoding="utf-8")

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
