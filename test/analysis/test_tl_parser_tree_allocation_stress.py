# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT

from __future__ import annotations

import pathlib
import sys
import unittest

THIS_DIR = pathlib.Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from tl_parser_test_helper import TD_API_SCHEMA, TlParserBinary  # noqa: E402


class TlParserTreeAllocationStressTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.binary = TlParserBinary()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.binary.cleanup()

    def test_repeated_large_valid_schema_runs_stay_stable(self) -> None:
        for _ in range(10):
            result = self.binary.run_schema_file(TD_API_SCHEMA)
            self.assertEqual(0, result.returncode, msg=result.stderr)
            self.assertNotIn("SIGSEGV received", result.stderr)
            self.assertNotIn("SIGABRT received", result.stderr)

    def test_repeated_truncated_schema_runs_fail_without_signals(self) -> None:
        schema = "double ? = Double\nstring ? = String\n" * 96
        for _ in range(10):
            result = self.binary.run_schema(schema)
            self.assertEqual(1, result.returncode, msg=result.stderr)
            self.assertNotIn("SIGSEGV received", result.stderr)
            self.assertNotIn("SIGABRT received", result.stderr)


if __name__ == "__main__":
    unittest.main()
