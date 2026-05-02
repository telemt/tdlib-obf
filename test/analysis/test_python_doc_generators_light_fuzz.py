# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs

from __future__ import annotations

import contextlib
import io
import pathlib
import random
import string
import sys
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
GENERATE_DIR = REPO_ROOT / "td" / "generate"

sys.path.insert(0, str(GENERATE_DIR))
from dotnet_tl_docs import DotnetTlDocumentationGenerator  # noqa: E402
from javadoc_tl_docs import JavadocTlDocumentationGenerator  # noqa: E402


class PythonDocGeneratorsLightFuzzTest(unittest.TestCase):
    def test_escape_documentation_light_fuzz_10000_iterations(self) -> None:
        rng = random.Random(20260502)
        alphabet = string.ascii_letters + string.digits + string.punctuation + " \t"

        javadoc_generator = JavadocTlDocumentationGenerator("", "", 8)
        dotnet_generator = DotnetTlDocumentationGenerator("Windows")

        for _ in range(10000):
            size = rng.randint(0, 128)
            payload = "".join(rng.choice(alphabet) for _ in range(size))

            javadoc_escaped = javadoc_generator.escape_documentation(payload)
            dotnet_escaped = dotnet_generator.escape_documentation(payload)

            self.assertIsInstance(javadoc_escaped, str)
            self.assertIsInstance(dotnet_escaped, str)
            self.assertNotIn("*/", javadoc_escaped)
            self.assertNotIn("*/", dotnet_escaped)

    def test_type_name_parser_light_fuzz_10000_iterations(self) -> None:
        rng = random.Random(20260503)
        alphabet = string.ascii_letters + string.digits + "._<>-[]{}:/\\"

        javadoc_generator = JavadocTlDocumentationGenerator("", "", 8)
        dotnet_generator = DotnetTlDocumentationGenerator("Windows")

        with contextlib.redirect_stderr(io.StringIO()):
            for _ in range(10000):
                size = rng.randint(0, 48)
                fuzzed_type = "".join(rng.choice(alphabet) for _ in range(size))

                javadoc_type_name = javadoc_generator.get_type_name(fuzzed_type)
                dotnet_type_name = dotnet_generator.get_type_name(fuzzed_type)

                self.assertIsInstance(javadoc_type_name, str)
                self.assertIsInstance(dotnet_type_name, str)


if __name__ == "__main__":
    unittest.main()
