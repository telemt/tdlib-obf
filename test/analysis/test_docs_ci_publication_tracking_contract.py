# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs

from __future__ import annotations

import pathlib
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DOCS_WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "doxygen-docs-integrity.yml"


class DocsCiPublicationTrackingContractTest(unittest.TestCase):
    def test_docs_workflow_emits_publication_manifest_contract(self) -> None:
        workflow = DOCS_WORKFLOW_PATH.read_text(encoding="utf-8")

        self.assertIn("docs_artifact_manifest.json", workflow)
        self.assertIn("${{ github.run_id }}", workflow)
        self.assertIn("${{ github.sha }}", workflow)
        self.assertIn("GITHUB_STEP_SUMMARY", workflow)
        self.assertIn("date -u +", workflow)

    def test_docs_workflow_uploads_manifest_with_html_artifact_contract(self) -> None:
        workflow = DOCS_WORKFLOW_PATH.read_text(encoding="utf-8")

        self.assertIn("build/docs/api/html", workflow)
        self.assertIn("build/docs/api/docs_artifact_manifest.json", workflow)


if __name__ == "__main__":
    unittest.main()
