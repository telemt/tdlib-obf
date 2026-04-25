#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs

from __future__ import annotations

import pathlib
import unittest


THIS_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = THIS_DIR.parents[1]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "fingerprint-policy-integrity.yml"


class FingerprintPolicyCiContractTest(unittest.TestCase):
    @staticmethod
    def _section_between(workflow_text: str, start_marker: str, end_marker: str) -> str:
        start_index = workflow_text.index(start_marker)
        end_index = workflow_text.index(end_marker, start_index)
        return workflow_text[start_index:end_index]

    def test_workflow_runs_on_pr_and_release_branches(self) -> None:
        workflow_text = WORKFLOW_PATH.read_text(encoding="utf-8")

        self.assertIn("pull_request:", workflow_text)
        self.assertIn("push:", workflow_text)
        self.assertIn("- 'release/**'", workflow_text)
        self.assertIn("- master", workflow_text)

    def test_workflow_has_single_schedule_block_and_single_nightly_cron(self) -> None:
        workflow_text = WORKFLOW_PATH.read_text(encoding="utf-8")

        self.assertEqual(1, workflow_text.count("schedule:"))
        self.assertEqual(1, workflow_text.count("- cron: '17 2 * * *'"))

    def test_workflow_has_explicit_distinct_reviewed_and_imported_job_names(self) -> None:
        workflow_text = WORKFLOW_PATH.read_text(encoding="utf-8")

        self.assertIn("reviewed_corpus_smoke:", workflow_text)
        self.assertIn("name: reviewed_corpus_smoke", workflow_text)
        self.assertIn("imported_corpus_smoke:", workflow_text)
        self.assertIn("name: imported_corpus_smoke", workflow_text)
        self.assertIn("continue-on-error: true", workflow_text)

    def test_workflow_executes_reviewed_and_imported_smoke_with_separate_registries(self) -> None:
        workflow_text = WORKFLOW_PATH.read_text(encoding="utf-8")

        self.assertIn("--registry test/analysis/profiles_validation.json", workflow_text)
        self.assertIn("--fixtures-root test/analysis/fixtures/clienthello", workflow_text)
        self.assertIn("--server-hello-fixtures-root test/analysis/fixtures/serverhello", workflow_text)

        self.assertIn("--registry test/analysis/profiles_imported.json", workflow_text)
        self.assertIn("--fixtures-root test/analysis/fixtures/imported/clienthello", workflow_text)
        self.assertIn("--server-hello-fixtures-root test/analysis/fixtures/imported/serverhello", workflow_text)

    def test_workflow_enforces_generator_drift_fail_closed(self) -> None:
        workflow_text = WORKFLOW_PATH.read_text(encoding="utf-8")

        self.assertIn("tier_semantics_drift_check:", workflow_text)
        self.assertIn("python3 test/analysis/build_transport_coherence_status.py --repo-root . --now-utc 2026-04-25T00:00:00Z", workflow_text)
        self.assertIn("python3 test/analysis/build_active_probing_status.py --repo-root . --now-utc 2026-04-25T00:00:00Z", workflow_text)
        self.assertIn("python3 test/analysis/render_fingerprint_policy_artifacts.py --repo-root . --now-utc 2026-04-25T00:00:00Z", workflow_text)
        self.assertIn("git diff --exit-code", workflow_text)
        self.assertIn("docs/Documentation/FINGERPRINT_TRANSPORT_COHERENCE_STATUS.generated.json", workflow_text)
        self.assertIn("docs/Documentation/FINGERPRINT_ACTIVE_PROBING_NIGHTLY_STATUS.generated.json", workflow_text)
        self.assertIn("docs/Documentation/FINGERPRINT_RELEASE_EVIDENCE_POLICY.generated.json", workflow_text)

    def test_workflow_trigger_paths_cover_generated_status_artifacts(self) -> None:
        workflow_text = WORKFLOW_PATH.read_text(encoding="utf-8")
        push_section = self._section_between(workflow_text, "  push:\n", "  pull_request:\n")
        pull_request_section = workflow_text[workflow_text.index("  pull_request:\n") :]

        self.assertIn("docs/Documentation/FINGERPRINT_TRANSPORT_COHERENCE_STATUS.generated.json", push_section)
        self.assertIn("docs/Documentation/FINGERPRINT_ACTIVE_PROBING_NIGHTLY_STATUS.generated.json", push_section)
        self.assertIn("docs/Documentation/FINGERPRINT_TRANSPORT_COHERENCE_STATUS.generated.json", pull_request_section)
        self.assertIn("docs/Documentation/FINGERPRINT_ACTIVE_PROBING_NIGHTLY_STATUS.generated.json", pull_request_section)

    def test_workflow_has_scheduled_active_probing_refresh_wrapper(self) -> None:
        workflow_text = WORKFLOW_PATH.read_text(encoding="utf-8")

        self.assertIn("schedule:", workflow_text)
        self.assertIn("active_probing_nightly_refresh:", workflow_text)
        self.assertIn("if: github.event_name == 'schedule'", workflow_text)
        self.assertIn("python3 test/analysis/refresh_active_probing_nightly_observations.py", workflow_text)
        self.assertIn("python3 test/analysis/build_active_probing_status.py", workflow_text)
        self.assertIn("test_refresh_active_probing_nightly_observations_contract.py", workflow_text)
        self.assertIn("uses: actions/upload-artifact@v4", workflow_text)
        self.assertIn("active-probing-nightly-evidence", workflow_text)


if __name__ == "__main__":
    unittest.main()
