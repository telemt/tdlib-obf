# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs

from __future__ import annotations

import pathlib
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
API_DOC_WORKFLOW_PATH = REPO_ROOT / "docs" / "Documentation" / "API_DOCUMENTATION.md"
DOXYFILE_TEMPLATE_PATH = REPO_ROOT / "Doxyfile.in"
CSHARP_README_PATH = REPO_ROOT / "example" / "csharp" / "README.md"
UWP_README_PATH = REPO_ROOT / "example" / "uwp" / "README.md"

# Risk test IDs covered by this module:
# - RISK-DOC-09
# - RISK-DOC-13


class ContributorDocDriftContractTest(unittest.TestCase):
    def test_api_workflow_doc_points_to_build_tree_api_docs_contract(self) -> None:
        workflow_doc = API_DOC_WORKFLOW_PATH.read_text(encoding="utf-8")

        self.assertIn("cmake --build build --target td_generate_api_docs", workflow_doc)
        self.assertIn("build/docs/api/html/index.html", workflow_doc)
        self.assertNotIn("docs/html/index.html", workflow_doc)

    def test_doxygen_template_mainpage_uses_dedicated_api_page_contract(self) -> None:
        doxygen_config = DOXYFILE_TEMPLATE_PATH.read_text(encoding="utf-8")

        self.assertIn(
            "USE_MDFILE_AS_MAINPAGE = @CMAKE_SOURCE_DIR@/docs/api/mainpage.md",
            doxygen_config,
        )
        self.assertNotIn("USE_MDFILE_AS_MAINPAGE = ./README.md", doxygen_config)

    def test_binding_specific_docs_use_python3_and_drop_php_prerequisites_contract(
        self,
    ) -> None:
        csharp_readme = CSHARP_README_PATH.read_text(encoding="utf-8")
        uwp_readme = UWP_README_PATH.read_text(encoding="utf-8")

        self.assertIn("Python 3", csharp_readme)
        self.assertIn("Python 3", uwp_readme)
        self.assertNotIn("php.exe", csharp_readme)
        self.assertNotIn("php.exe", uwp_readme)
        self.assertNotIn("PHP", csharp_readme)
        self.assertNotIn("PHP", uwp_readme)


if __name__ == "__main__":
    unittest.main()
