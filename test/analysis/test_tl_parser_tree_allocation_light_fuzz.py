# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT

from __future__ import annotations

import pathlib
import random
import sys
import unittest

THIS_DIR = pathlib.Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from tl_parser_test_helper import TlParserBinary  # noqa: E402


class TlParserTreeAllocationLightFuzzTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.binary = TlParserBinary()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.binary.cleanup()

    def test_random_schema_noise_never_crashes_parser(self) -> None:
        rng = random.Random(20260428)
        alphabet = "-=?;#[](){}_ abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\n"
        for _ in range(24):
            payload = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 256)))
            result = self.binary.run_schema(payload)
            self.assertIn(result.returncode, (0, 1), msg=result.stderr)
            self.assertNotIn("SIGSEGV received", result.stderr)
            self.assertNotIn("SIGABRT received", result.stderr)


if __name__ == "__main__":
    unittest.main()
