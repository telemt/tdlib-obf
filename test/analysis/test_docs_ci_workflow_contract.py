# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs

from __future__ import annotations

import pathlib
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DOCS_WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "doxygen-docs-integrity.yml"


class DocsCiWorkflowContractTest(unittest.TestCase):
    def test_docs_ci_workflow_exists(self) -> None:
        self.assertTrue(
            DOCS_WORKFLOW_PATH.exists(),
            msg="Missing docs CI workflow required for post-milestone Doxygen publication",
        )

    def test_docs_ci_workflow_runs_docs_contracts_and_builds_artifact(self) -> None:
        workflow = DOCS_WORKFLOW_PATH.read_text(encoding="utf-8")

        self.assertIn("name: Doxygen Docs Integrity", workflow)
        self.assertIn("actions/setup-python@v5", workflow)
        self.assertIn("actions/setup-node@v4", workflow)
        self.assertIn("node-version: 24.15.0", workflow)
        self.assertIn("cmake --build build --target td_generate_api_docs", workflow)
        self.assertIn("build/docs/api/html/index.html", workflow)
        self.assertIn("actions/upload-artifact@v4", workflow)

        self.assertIn(
            "python3 -m unittest discover -s test/analysis -p 'test_*doxygen*.py'",
            workflow,
        )
        self.assertIn(
            "python3 -m unittest discover -s test/analysis -p 'test_*doc*contract.py'",
            workflow,
        )
        self.assertIn(
            "- '.gitignore'",
            workflow,
            msg="Docs CI must run when .gitignore changes to enforce Python-cache hygiene contracts",
        )


if __name__ == "__main__":
    unittest.main()
