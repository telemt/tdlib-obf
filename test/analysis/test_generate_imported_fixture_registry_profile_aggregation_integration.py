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
    write_serverhello_artifact,
)


class GenerateImportedFixtureRegistryProfileAggregationIntegrationTest(
    unittest.TestCase
):
    def test_aggregated_profile_still_pairs_with_serverhello_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = pathlib.Path(temp_dir)
            capture_a = base / "captures" / "a.pcapng"
            capture_b = base / "captures" / "b.pcapng"
            capture_a.parent.mkdir(parents=True, exist_ok=True)
            capture_a.write_text("a\n", encoding="utf-8")
            capture_b.write_text("b\n", encoding="utf-8")

            clienthello_root = base / "imported" / "clienthello"
            serverhello_root = base / "imported" / "serverhello"
            manifest_path = base / "imported" / "import_manifest.json"
            registry_path = base / "profiles_imported.json"

            profile_id = "chrome146_windows_test"
            write_clienthello_artifact(
                clienthello_root / "windows" / "part1.clienthello.json",
                profile_id=profile_id,
                source_path=capture_a,
                route_mode="unknown",
                samples=[
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
            )
            write_clienthello_artifact(
                clienthello_root / "windows" / "part2.clienthello.json",
                profile_id=profile_id,
                source_path=capture_b,
                route_mode="unknown",
                samples=[
                    {
                        "fixture_id": f"{profile_id}:frame2",
                        "cipher_suites": ["0x1301"],
                        "supported_groups": ["0x001D", "0x11EC"],
                        "key_share_entries": [{"group": "0x001D"}, {"group": "0x11EC"}],
                        "non_grease_extensions_without_padding": [
                            "0x000D",
                            "0x002B",
                            "0x44CD",
                        ],
                        "alpn_protocols": ["h2"],
                        "extensions": [{"type": "0x44CD", "body_hex": ""}],
                        "ech": None,
                    }
                ],
            )
            write_serverhello_artifact(
                serverhello_root / "windows" / "serverhello.json",
                family=profile_id,
                source_path=capture_a,
                route_mode="unknown",
            )

            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            manifest_path.write_text(
                json.dumps(
                    {
                        "version": "imported-capture-corpus-v1",
                        "entries": [
                            {
                                "capture_path": str(capture_a.resolve()),
                                "profile_id": profile_id,
                                "browser_alias": "chrome",
                                "route_mode": "unknown",
                            },
                            {
                                "capture_path": str(capture_b.resolve()),
                                "profile_id": profile_id,
                                "browser_alias": "chrome",
                                "route_mode": "unknown",
                            },
                        ],
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

            self.assertIn(profile_id, registry["profiles"])
            self.assertIn(profile_id, registry["server_hello_matrix"])
            self.assertEqual(
                registry["server_hello_matrix"][profile_id]["allowed_tuples"][0][
                    "selected_version"
                ],
                "0x0304",
            )
            self.assertEqual(
                len(registry["profiles"][profile_id]["include_fixture_ids"]),
                2,
            )


if __name__ == "__main__":
    unittest.main()
