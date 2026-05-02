# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs

from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
GENERATOR = REPO_ROOT / "td" / "generate" / "doxygen_tl_docs.py"
SCHEME = REPO_ROOT / "td" / "generate" / "scheme" / "td_api.tl"
HEADER = REPO_ROOT / "td" / "generate" / "auto" / "td" / "telegram" / "td_api.h"
TD_GENERATE_CMAKE = REPO_ROOT / "td" / "generate" / "CMakeLists.txt"
ROOT_CMAKE = REPO_ROOT / "CMakeLists.txt"


class TdApiDoxygenGeneratorContractTest(unittest.TestCase):
    def test_python_generator_injects_doxygen_comments_into_td_api_header(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_header = pathlib.Path(tmp_dir) / "td_api.h"
            shutil.copy2(HEADER, tmp_header)

            completed = subprocess.run(
                [sys.executable, str(GENERATOR), str(SCHEME), str(tmp_header)],
                check=True,
                capture_output=True,
                text=True,
            )

            self.assertEqual(completed.stderr, "")

            rendered = tmp_header.read_text(encoding="utf-8")
            self.assertIn(
                "Contains declarations of all functions and types which represent a public TDLib interface.",
                rendered,
            )
            self.assertIn(
                "This class is a base class for all TDLib API classes.", rendered
            )
            self.assertIn(
                "Provides information about the method by which an authentication code is delivered to the user.",
                rendered,
            )
            self.assertIn(
                "An object of this type is returned on a successful function call for certain functions.",
                rendered,
            )

    def test_build_pipeline_prefers_python_generator_and_exposes_doxygen_target(
        self,
    ) -> None:
        td_generate_cmake = TD_GENERATE_CMAKE.read_text(encoding="utf-8")
        self.assertRegex(
            td_generate_cmake,
            r"find_package\(\s*Python3\s+COMPONENTS\s+Interpreter\s+QUIET\s*\)",
        )
        self.assertIn("doxygen_tl_docs.py", td_generate_cmake)
        self.assertNotIn(
            "DoxygenTlDocumentationGenerator.php ../scheme/td_api.tl td/telegram/td_api.h",
            td_generate_cmake,
        )

        root_cmake = ROOT_CMAKE.read_text(encoding="utf-8")
        self.assertIn("find_package(Doxygen QUIET)", root_cmake)
        self.assertIn("td_generate_api_docs", root_cmake)

    def test_doxygen_cli_uses_shared_tl_doc_core_only(self) -> None:
        generator_source = GENERATOR.read_text(encoding="utf-8")

        self.assertIn(
            "from tl_doc_core import TlDocumentationGenerator as SharedTlDocumentationGenerator",
            generator_source,
        )
        self.assertIn(
            "class DoxygenTlDocumentationGenerator(SharedTlDocumentationGenerator):",
            generator_source,
        )
        self.assertNotIn("class TlDocumentationGenerator:\n", generator_source)


if __name__ == "__main__":
    unittest.main()
