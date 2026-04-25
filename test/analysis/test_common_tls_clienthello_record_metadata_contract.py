# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs

from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest


THIS_DIR = pathlib.Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from common_tls import load_clienthello_artifact  # noqa: E402


def make_clienthello_artifact() -> dict:
    return {
        "artifact_type": "tls_clienthello_fixtures",
        "parser_version": "tls-clienthello-parser-v1",
        "profile_id": "test_profile",
        "route_mode": "non_ru_egress",
        "device_class": "desktop",
        "os_family": "linux",
        "transport": "tcp",
        "source_kind": "browser_capture",
        "source_path": "/synthetic/capture.pcapng",
        "source_sha256": "1" * 64,
        "scenario_id": "scenario_alpha",
        "samples": [
            {
                "fixture_id": "test_profile:frame1",
                "fixture_family_id": "family_alpha",
                "record_length": 512,
                "record_lengths": [512],
                "record_count": 1,
                "cipher_suites": ["0x1301", "0x1302"],
                "supported_groups": ["0x001D"],
                "extensions": [],
                "non_grease_extensions_without_padding": [],
                "alpn_protocols": ["h2"],
                "key_share_entries": [{"group": "0x001D"}],
                "ech": None,
            }
        ],
    }


class CommonTlsClientHelloRecordMetadataContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _write(self, name: str, payload: dict) -> pathlib.Path:
        path = self.root / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_accepts_consistent_record_shape_metadata(self) -> None:
        samples = load_clienthello_artifact(self._write("valid.clienthello.json", make_clienthello_artifact()))

        self.assertEqual(1, len(samples))

    def test_rejects_record_count_drift_from_record_lengths(self) -> None:
        payload = make_clienthello_artifact()
        payload["samples"][0]["record_count"] = 2

        with self.assertRaisesRegex(ValueError, "record_count"):
            load_clienthello_artifact(self._write("bad_record_count.clienthello.json", payload))

    def test_rejects_record_length_drift_from_record_lengths_sum(self) -> None:
        payload = make_clienthello_artifact()
        payload["samples"][0]["record_lengths"] = [256, 255]
        payload["samples"][0]["record_count"] = 2

        with self.assertRaisesRegex(ValueError, "record_length"):
            load_clienthello_artifact(self._write("bad_record_length.clienthello.json", payload))

    def test_rejects_record_count_without_record_lengths(self) -> None:
        payload = make_clienthello_artifact()
        del payload["samples"][0]["record_lengths"]

        with self.assertRaisesRegex(ValueError, "record_lengths"):
            load_clienthello_artifact(self._write("missing_record_lengths.clienthello.json", payload))

    def test_rejects_non_positive_or_oversized_record_lengths(self) -> None:
        for bad_value in (0, -7, 70000):
            with self.subTest(bad_value=bad_value):
                payload = make_clienthello_artifact()
                payload["samples"][0]["record_lengths"] = [bad_value]

                with self.assertRaisesRegex(ValueError, "record_lengths"):
                    load_clienthello_artifact(self._write(f"bad_record_length_{bad_value}.clienthello.json", payload))


if __name__ == "__main__":
    unittest.main()