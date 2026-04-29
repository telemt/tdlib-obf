# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs

import pathlib
import tempfile
import unittest
from argparse import Namespace

from import_traffic_dumps import (
    derive_capture_plan,
    iter_unsorted_captures,
    resolve_captures,
)


class ImportTrafficDumpsAdversarialTest(unittest.TestCase):
    def test_rejects_capture_with_ambiguous_browser_token(self) -> None:
        with self.assertRaisesRegex(ValueError, "unable to classify browser"):
            derive_capture_plan(
                pathlib.Path(
                    "Windows_11,_Chrome_and_Firefox,_auto_Windows_11,_auto_Chrome.pcap"
                )
            )

    def test_rejects_capture_with_ambiguous_platform_token(self) -> None:
        with self.assertRaisesRegex(ValueError, "unable to classify platform"):
            derive_capture_plan(
                pathlib.Path(
                    "Android_iOS_mixed,_Safari_26_5,_auto_iOS_18_7,_auto_Safari.pcap"
                )
            )

    def test_iter_unsorted_captures_rejects_symlinked_capture(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            outside_capture = root / "outside.pcap"
            outside_capture.write_bytes(b"pcap")
            symlink_capture = root / "linked_capture.pcap"
            symlink_capture.symlink_to(outside_capture)

            captures = iter_unsorted_captures(root)

            self.assertNotIn(symlink_capture, captures)

    def test_resolve_captures_rejects_explicit_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            outside_capture = root / "outside.pcapng"
            outside_capture.write_bytes(b"pcapng")
            symlink_capture = root / "linked_capture.pcapng"
            symlink_capture.symlink_to(outside_capture)

            args = Namespace(capture=[str(symlink_capture)], unsorted_root=str(root))

            with self.assertRaisesRegex(SystemExit, "symlink"):
                resolve_captures(args)


if __name__ == "__main__":
    unittest.main()
