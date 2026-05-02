# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs

from __future__ import annotations

import pathlib
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DOXYFILE_TEMPLATE_PATH = REPO_ROOT / "Doxyfile.in"
ROOT_CMAKE_PATH = REPO_ROOT / "CMakeLists.txt"
TD_GENERATE_CMAKE_PATH = REPO_ROOT / "td" / "generate" / "CMakeLists.txt"
API_MAINPAGE_PATH = REPO_ROOT / "docs" / "api" / "mainpage.md"
PUBLIC_SURFACE_POLICY_PATH = REPO_ROOT / "docs" / "api" / "public_api_surfaces.md"

# Risk test IDs covered by this module:
# - RISK-DOC-01
# - RISK-DOC-05
# - RISK-DOC-09
# - RISK-DOC-10
# - RISK-DOC-11


class DoxygenBuildContractTest(unittest.TestCase):
    def test_doxyfile_template_uses_build_local_output_and_api_mainpage(self) -> None:
        self.assertTrue(
            DOXYFILE_TEMPLATE_PATH.exists(),
            msg="Milestone 1 requires a configured Doxyfile template",
        )

        doxygen_config = DOXYFILE_TEMPLATE_PATH.read_text(encoding="utf-8")

        self.assertIn(
            'OUTPUT_DIRECTORY       = "@TDLIB_DOXYGEN_OUTPUT_DIRECTORY@"',
            doxygen_config,
        )
        self.assertIn(
            "USE_MDFILE_AS_MAINPAGE = @CMAKE_SOURCE_DIR@/docs/api/mainpage.md",
            doxygen_config,
        )

    def test_doxyfile_template_defines_curated_public_input_policy(self) -> None:
        doxygen_config = DOXYFILE_TEMPLATE_PATH.read_text(encoding="utf-8")

        self.assertIn("INPUT                  =", doxygen_config)
        for expected_public_input in (
            "@CMAKE_SOURCE_DIR@/td/generate/auto/td/telegram/td_api.h",
            "@CMAKE_SOURCE_DIR@/td/generate/auto/td/telegram/td_api.hpp",
            "@CMAKE_SOURCE_DIR@/td/tl/TlObject.h",
            "@CMAKE_SOURCE_DIR@/td/telegram/Client.h",
            "@CMAKE_SOURCE_DIR@/td/telegram/td_json_client.h",
            "@CMAKE_SOURCE_DIR@/docs/api/mainpage.md",
            "@CMAKE_SOURCE_DIR@/docs/api/public_api_surfaces.md",
        ):
            self.assertIn(
                expected_public_input,
                doxygen_config,
                msg="Doxygen public-surface input contract changed unexpectedly",
            )
        self.assertNotIn("ClientActor.h", doxygen_config)
        self.assertNotIn("./README.md", doxygen_config)

    def test_api_landing_and_surface_policy_files_exist(self) -> None:
        self.assertTrue(API_MAINPAGE_PATH.exists())
        self.assertTrue(PUBLIC_SURFACE_POLICY_PATH.exists())

    def test_root_docs_target_uses_configured_template_in_build_tree(self) -> None:
        root_cmake = ROOT_CMAKE_PATH.read_text(encoding="utf-8")

        self.assertIn("find_package(Doxygen QUIET)", root_cmake)
        self.assertIn("Doxyfile.in", root_cmake)
        self.assertIn("td_generate_api_docs", root_cmake)
        self.assertRegex(
            root_cmake,
            r"configure_file\(\s*\"\$\{CMAKE_CURRENT_SOURCE_DIR\}/Doxyfile\.in\"",
        )
        self.assertRegex(
            root_cmake,
            r"COMMAND\s+\$\{DOXYGEN_EXECUTABLE\}\s+\$\{CMAKE_CURRENT_BINARY_DIR\}/Doxyfile\.api",
        )
        self.assertRegex(
            root_cmake,
            r"COMMAND\s+\$\{CMAKE_COMMAND\}\s+-E\s+make_directory\s+\$\{TDLIB_DOXYGEN_OUTPUT_DIRECTORY\}",
        )
        self.assertIn("WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}", root_cmake)
        self.assertIn("DEPENDS tl_generate_common", root_cmake)
        self.assertIn("build/docs/api", root_cmake)

    def test_python_injection_runs_whenever_python_exists_contract(self) -> None:
        td_generate_cmake = TD_GENERATE_CMAKE_PATH.read_text(encoding="utf-8")

        self.assertIn(
            "if(Python3_EXECUTABLE)",
            td_generate_cmake,
        )
        self.assertNotIn(
            "if(Python3_EXECUTABLE AND NOT TD_ENABLE_DOTNET)",
            td_generate_cmake,
        )
        self.assertIn(
            "generated td_api.h will not contain injected Doxygen comments",
            td_generate_cmake,
        )

    def test_migration_guardrail_python_injection_must_not_be_dotnet_gated(
        self,
    ) -> None:
        td_generate_cmake = TD_GENERATE_CMAKE_PATH.read_text(encoding="utf-8")

        self.assertNotIn(
            "if(Python3_EXECUTABLE AND NOT TD_ENABLE_DOTNET)",
            td_generate_cmake,
            msg="RISK-DOC-01: Python Doxygen injection must be decoupled from TD_ENABLE_DOTNET",
        )

    def test_public_surface_policy_describes_exclusions(self) -> None:
        policy_text = PUBLIC_SURFACE_POLICY_PATH.read_text(encoding="utf-8")

        self.assertRegex(policy_text, r"(?i)public api")
        self.assertRegex(policy_text, r"(?i)excluded")
        self.assertRegex(policy_text, r"ClientActor\.h")


if __name__ == "__main__":
    unittest.main()