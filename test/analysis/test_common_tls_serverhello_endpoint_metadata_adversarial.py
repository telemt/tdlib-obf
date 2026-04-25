# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs

from __future__ import annotations

import copy
import json
import pathlib
import sys
import tempfile
import unittest


THIS_DIR = pathlib.Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from common_tls import load_server_hello_artifact  # noqa: E402


def make_serverhello_artifact() -> dict:
    endpoint = {"ip": "142.250.186.46", "port": 443}
    return {
        "artifact_type": "tls_serverhello_fixtures",
        "parser_version": "tls-serverhello-parser-v1",
        "route_mode": "non_ru_egress",
        "scenario_id": "scenario_alpha",
        "source_path": "/synthetic/capture.pcapng",
        "source_sha256": "2" * 64,
        "source_kind": "browser_capture",
        "transport": "tcp",
        "family": "family_alpha",
        "capture_provenance": {
            "client_profile_id": "test_profile",
        },
        "observed_server_endpoints": [endpoint],
        "samples": [
            {
                "fixture_id": "test_profile:frame1",
                "fixture_family_id": "family_alpha",
                "selected_version": "0x0304",
                "cipher_suite": "0x1301",
                "extensions": ["0x002B", "0x0033"],
                "record_layout_signature": [22],
                "server_endpoint": endpoint,
            }
        ],
    }


class CommonTlsServerHelloEndpointMetadataAdversarialTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _write(self, name: str, payload: dict) -> pathlib.Path:
        path = self.root / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_accepts_consistent_observed_endpoint_metadata(self) -> None:
        samples = load_server_hello_artifact(self._write("valid.serverhello.json", make_serverhello_artifact()))

        self.assertEqual(1, len(samples))
        self.assertIsNotNone(samples[0].server_endpoint)

    def test_rejects_invalid_sample_server_endpoint_shape(self) -> None:
        payload = make_serverhello_artifact()
        payload["samples"][0]["server_endpoint"] = {"ip": "", "port": 0}

        with self.assertRaisesRegex(ValueError, "server_endpoint"):
            load_server_hello_artifact(self._write("bad_sample_endpoint.serverhello.json", payload))

    def test_rejects_duplicate_observed_server_endpoints(self) -> None:
        payload = make_serverhello_artifact()
        payload["observed_server_endpoints"] = [
            {"ip": "142.250.186.46", "port": 443},
            {"ip": "142.250.186.46", "port": 443},
        ]

        with self.assertRaisesRegex(ValueError, "observed_server_endpoints"):
            load_server_hello_artifact(self._write("dup_observed_endpoint.serverhello.json", payload))

    def test_rejects_sample_endpoint_not_listed_in_observed_endpoints(self) -> None:
        payload = make_serverhello_artifact()
        payload["samples"][0]["server_endpoint"] = {"ip": "142.250.186.46", "port": 8443}

        with self.assertRaisesRegex(ValueError, "observed_server_endpoints"):
            load_server_hello_artifact(self._write("sample_endpoint_drift.serverhello.json", payload))

    def test_rejects_observed_endpoint_not_seen_in_samples(self) -> None:
        payload = make_serverhello_artifact()
        payload["observed_server_endpoints"].append({"ip": "142.250.186.46", "port": 8443})

        with self.assertRaisesRegex(ValueError, "observed_server_endpoints"):
            load_server_hello_artifact(self._write("observed_endpoint_drift.serverhello.json", payload))


if __name__ == "__main__":
    unittest.main()