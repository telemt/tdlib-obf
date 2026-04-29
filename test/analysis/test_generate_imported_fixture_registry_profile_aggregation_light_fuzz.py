# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs

import json
import pathlib
import random
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


def _sample_template(profile_id: str, frame: int) -> dict:
    has_ech = (frame % 2) == 0
    has_alps = (frame % 3) == 0
    has_pq = (frame % 5) == 0
    extensions = []
    if has_ech:
        extensions.append({"type": "0xFE0D", "body_hex": ""})
    if has_alps:
        extensions.append({"type": "0x44CD", "body_hex": ""})

    supported_groups = ["0x001D"]
    key_share_entries = [{"group": "0x001D"}]
    if has_pq:
        supported_groups.append("0x11EC")
        key_share_entries.append({"group": "0x11EC"})

    non_grease = ["0x000D", "0x002B"]
    if has_alps:
        non_grease.append("0x44CD")

    return {
        "fixture_id": f"{profile_id}:frame{frame}",
        "cipher_suites": ["0x1301"],
        "supported_groups": supported_groups,
        "key_share_entries": key_share_entries,
        "non_grease_extensions_without_padding": non_grease,
        "alpn_protocols": ["h2"],
        "extensions": extensions,
        "ech": {"payload_length": 208} if has_ech else None,
    }


class GenerateImportedFixtureRegistryProfileAggregationLightFuzzTest(unittest.TestCase):
    def test_partitioning_across_artifacts_preserves_profile_policy(self) -> None:
        profile_id = "chrome146_windows_test"
        all_samples = [_sample_template(profile_id, frame) for frame in range(1, 33)]

        for seed in range(32):
            with self.subTest(seed=seed):
                rng = random.Random(seed)
                with tempfile.TemporaryDirectory() as temp_dir:
                    base = pathlib.Path(temp_dir)
                    clienthello_root = base / "imported" / "clienthello"
                    serverhello_root = base / "imported" / "serverhello"
                    manifest_path = base / "imported" / "import_manifest.json"
                    registry_path = base / "profiles_imported.json"

                    captures = []
                    for index in range(8):
                        capture = base / "captures" / f"{index}.pcapng"
                        capture.parent.mkdir(parents=True, exist_ok=True)
                        capture.write_text(f"{index}\n", encoding="utf-8")
                        captures.append(capture)

                    buckets: list[list[dict]] = [[] for _ in range(8)]
                    for bucket_index, sample in enumerate(all_samples[: len(buckets)]):
                        buckets[bucket_index].append(sample)
                    for sample in all_samples[len(buckets) :]:
                        buckets[rng.randrange(len(buckets))].append(sample)

                    manifest_entries = []
                    for index, bucket in enumerate(buckets):
                        capture = captures[index]
                        write_clienthello_artifact(
                            clienthello_root / "windows" / f"part_{index}.json",
                            profile_id=profile_id,
                            source_path=capture,
                            route_mode="unknown",
                            samples=bucket,
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
                    profile = registry["profiles"][profile_id]

                    self.assertEqual(
                        profile["ech_type"],
                        {"allow_present": True, "allow_absent": True},
                    )
                    self.assertEqual(
                        profile["alps_type"],
                        {"allowed_types": ["0x44CD"], "allow_absent": True},
                    )
                    self.assertEqual(
                        profile["pq_group"],
                        {"allowed_groups": ["0x11EC"], "allow_absent": True},
                    )


if __name__ == "__main__":
    unittest.main()
