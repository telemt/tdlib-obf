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

from generate_imported_fixture_registry import (  # noqa: E402
    refresh_imported_candidate_corpus,
)
from test_generate_imported_fixture_registry import (  # noqa: E402
    write_clienthello_artifact,
)


class GenerateImportedFixtureRegistryProfileAggregationStressTest(unittest.TestCase):
    def test_large_number_of_split_artifacts_keeps_all_fixture_ids(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = pathlib.Path(temp_dir)
            clienthello_root = base / "imported" / "clienthello"
            serverhello_root = base / "imported" / "serverhello"
            manifest_path = base / "imported" / "import_manifest.json"
            registry_path = base / "profiles_imported.json"

            profile_id = "chrome146_windows_test"
            artifact_count = 180
            manifest_entries = []
            expected_fixture_ids = set()

            for index in range(artifact_count):
                capture = base / "captures" / f"{index}.pcapng"
                capture.parent.mkdir(parents=True, exist_ok=True)
                capture.write_text(f"{index}\n", encoding="utf-8")
                fixture_id = f"{profile_id}:frame{index + 1}"
                expected_fixture_ids.add(fixture_id)
                write_clienthello_artifact(
                    clienthello_root / "windows" / f"part_{index}.json",
                    profile_id=profile_id,
                    source_path=capture,
                    route_mode="unknown",
                    samples=[
                        {
                            "fixture_id": fixture_id,
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
                    ],
                )
                manifest_entries.append(
                    {
                        "capture_path": str(capture.resolve()),
                        "profile_id": profile_id,
                        "browser_alias": "chrome",
                        "route_mode": "unknown",
                    }
                )

            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            manifest_path.write_text(
                json.dumps(
                    {
                        "version": "imported-capture-corpus-v1",
                        "entries": manifest_entries,
                    }
                ),
                encoding="utf-8",
            )

            registry = refresh_imported_candidate_corpus(
                clienthello_root,
                serverhello_root,
                manifest_path,
                registry_path,
                "non_ru_egress",
            )

            include_fixture_ids = registry["profiles"][profile_id][
                "include_fixture_ids"
            ]
            self.assertEqual(len(include_fixture_ids), artifact_count)
            self.assertEqual(set(include_fixture_ids), expected_fixture_ids)


if __name__ == "__main__":
    unittest.main()
