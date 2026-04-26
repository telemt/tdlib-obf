#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT

from __future__ import annotations

import json
import pathlib
import tempfile
import unittest
from unittest import mock

import extract_client_hello_fixtures as extractor


class ExtractClientHelloSynMetadataIntegration(unittest.TestCase):
    def test_main_writes_syn_transport_traits_per_sample(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = pathlib.Path(tmp_dir)
            pcap_path = tmp_path / "capture.pcapng"
            out_path = tmp_path / "out.clienthello.json"
            pcap_path.write_bytes(b"pcap")

            frames = [
                {
                    "frame_number": "10",
                    "frame_time_epoch": "1714060800.0",
                    "tcp_stream": "3",
                    "tls_record_version": "0x0303",
                    "tls_record_length": "512",
                    "tls_handshake_type": "1",
                    "tcp_reassembled_data": "1603030001010000fd0303" + "00" * 245,
                    "tcp_payload": "",
                    "tls_handshake_fragment": "",
                }
            ]
            parsed_client_hello = {
                "record_version": "0x0303",
                "record_length": 512,
                "handshake_type": 1,
                "record_lengths": [512],
            }
            syn_traits = {
                "available": True,
                "ttl_bucket": "ttl_33_64",
                "mss_bucket": "mss_1201_1460",
                "window_scale_bucket": "wscale_6_8",
                "syn_option_order_class": "2-4-8-1-3",
                "ipid_behavior_class": "nonzero",
            }

            argv = [
                "extract_client_hello_fixtures.py",
                "--pcap",
                str(pcap_path),
                "--out",
                str(out_path),
                "--profile-id",
                "wave3_profile",
                "--route-mode",
                "non_ru_egress",
                "--device-class",
                "desktop",
                "--os-family",
                "linux",
            ]

            with mock.patch("extract_client_hello_fixtures.collect_frames", return_value=frames), \
                 mock.patch("extract_client_hello_fixtures.parse_client_hello", return_value=parsed_client_hello), \
                 mock.patch("extract_client_hello_fixtures.collect_syn_transport_traits_for_stream", return_value=syn_traits), \
                 mock.patch("extract_client_hello_fixtures.read_sha256", return_value="0" * 64), \
                 mock.patch("extract_client_hello_fixtures.tshark_version", return_value="tshark 4.4.0"), \
                 mock.patch("sys.argv", argv):
                rc = extractor.main()

            self.assertEqual(0, rc)
            payload = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertIn("samples", payload)
            self.assertEqual(1, len(payload["samples"]))
            self.assertEqual(syn_traits, payload["samples"][0]["syn_transport_traits"])


if __name__ == "__main__":
    unittest.main()
