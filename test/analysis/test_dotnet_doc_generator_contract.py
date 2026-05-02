# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs

from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
TD_GENERATE_CMAKE_PATH = REPO_ROOT / "td" / "generate" / "CMakeLists.txt"
TD_API_TL_PATH = REPO_ROOT / "td" / "generate" / "scheme" / "td_api.tl"
DOTNET_PYTHON_GENERATOR_PATH = REPO_ROOT / "td" / "generate" / "dotnet_tl_docs.py"
DOTNET_CSHARP_README_PATH = REPO_ROOT / "example" / "csharp" / "README.md"
DOTNET_UWP_README_PATH = REPO_ROOT / "example" / "uwp" / "README.md"
SHARED_PYTHON_CORE_PATH = REPO_ROOT / "td" / "generate" / "tl_doc_core.py"

# Risk test IDs covered by this module:
# - RISK-DOC-06
# - RISK-DOC-08


class DotnetDocGeneratorContractTest(unittest.TestCase):
    def test_td_generate_cmake_uses_python_for_dotnet_docs_contract(self) -> None:
        td_generate_cmake = TD_GENERATE_CMAKE_PATH.read_text(encoding="utf-8")

        self.assertIn("if(TD_ENABLE_DOTNET)", td_generate_cmake)
        self.assertIn("dotnet_tl_docs.py", td_generate_cmake)
        self.assertIn("${Python3_EXECUTABLE}", td_generate_cmake)
        self.assertIn("generate_dotnet_api", td_generate_cmake)
        self.assertNotIn("if(PHP_EXECUTABLE)", td_generate_cmake)
        self.assertNotIn("DotnetTlDocumentationGenerator.php", td_generate_cmake)

    def test_dotnet_example_readmes_drop_php_prerequisite_contract(
        self,
    ) -> None:
        csharp_readme = DOTNET_CSHARP_README_PATH.read_text(encoding="utf-8")
        uwp_readme = DOTNET_UWP_README_PATH.read_text(encoding="utf-8")

        self.assertIn("Python 3", csharp_readme)
        self.assertIn("Python 3", uwp_readme)
        self.assertNotIn("php.exe", csharp_readme)
        self.assertNotIn("php.exe", uwp_readme)
        self.assertNotIn("PHP", csharp_readme)
        self.assertNotIn("PHP", uwp_readme)

    def test_dotnet_python_generator_emits_representative_xml_contract(self) -> None:
        self.assertTrue(DOTNET_PYTHON_GENERATOR_PATH.exists())

        with tempfile.TemporaryDirectory() as tmp_dir:
            xml_output = pathlib.Path(tmp_dir) / "Telegram.Td.xml"
            subprocess.run(
                [
                    sys.executable,
                    str(DOTNET_PYTHON_GENERATOR_PATH),
                    str(TD_API_TL_PATH),
                    str(xml_output),
                    "Windows",
                ],
                check=True,
                capture_output=True,
                text=True,
            )

            rendered = xml_output.read_text(encoding="utf-8")
            self.assertIn('<?xml version="1.0"?>', rendered)
            self.assertIn('<member name="T:Telegram.Td.Api.Object">', rendered)
            self.assertIn('<member name="T:Telegram.Td.Client">', rendered)
            self.assertIn(
                '<member name="M:Telegram.Td.Client.Create(Telegram.Td.ClientResultHandler)">',
                rendered,
            )
            self.assertIn("</doc>", rendered)

    def test_dotnet_cli_uses_shared_python_doc_core(self) -> None:
        generator_source = DOTNET_PYTHON_GENERATOR_PATH.read_text(encoding="utf-8")

        self.assertIn(
            "from tl_doc_core import TlDocumentationGenerator as SharedTlDocumentationGenerator",
            generator_source,
        )
        self.assertIn(
            "class DotnetTlDocumentationGenerator(SharedTlDocumentationGenerator):",
            generator_source,
        )
        self.assertNotIn("class TlDocumentationGenerator:\n", generator_source)

    def test_migration_guardrail_requires_shared_python_doc_core(self) -> None:
        self.assertTrue(
            SHARED_PYTHON_CORE_PATH.exists(),
            msg="RISK-DOC-06: shared Python TL documentation core (tl_doc_core.py) must exist",
        )

    def test_migration_guardrail_dotnet_path_must_not_be_php_optional(self) -> None:
        td_generate_cmake = TD_GENERATE_CMAKE_PATH.read_text(encoding="utf-8")
        dotnet_block_start = td_generate_cmake.find("if(TD_ENABLE_DOTNET)")
        self.assertNotEqual(-1, dotnet_block_start)

        dotnet_block = td_generate_cmake[dotnet_block_start:]
        self.assertNotIn(
            "if(PHP_EXECUTABLE)",
            dotnet_block,
            msg="RISK-DOC-08: .NET docs generation must not silently degrade behind optional PHP availability",
        )
        self.assertNotIn(
            "DotnetTlDocumentationGenerator.php",
            dotnet_block,
            msg="RISK-DOC-08: .NET docs generation must not invoke legacy PHP generator",
        )
        self.assertIn("dotnet_tl_docs.py", dotnet_block)
        self.assertIn("${Python3_EXECUTABLE}", dotnet_block)


if __name__ == "__main__":
    unittest.main()
