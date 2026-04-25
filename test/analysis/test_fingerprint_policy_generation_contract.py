#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs

from __future__ import annotations

import pathlib
import sys
import unittest


THIS_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = THIS_DIR.parents[1]
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

import render_fingerprint_policy_artifacts as policy_artifacts  # noqa: E402


SPEC_PATH = THIS_DIR / "fingerprint_trust_tiers.json"
DOC_INDEX = REPO_ROOT / "docs" / "Documentation" / "FINGERPRINT_DOCUMENTATION_INDEX.md"
DOC_PIPELINE = REPO_ROOT / "docs" / "Documentation" / "FINGERPRINT_GENERATION_PIPELINE.md"
DOC_OPS = REPO_ROOT / "docs" / "Documentation" / "FINGERPRINT_OPERATIONS_GUIDE.md"


class FingerprintPolicyGenerationContractTest(unittest.TestCase):
    def test_contract_tier_thresholds_use_plan_values(self) -> None:
        spec = policy_artifacts.load_tier_spec(SPEC_PATH)
        policy_artifacts.validate_tier_spec(spec)

        tiers = {entry["tier"]: entry for entry in spec["tiers"]}
        self.assertEqual(0, tiers["Tier0"]["min_authoritative_captures"])
        self.assertEqual(3, tiers["Tier2"]["min_authoritative_captures"])
        self.assertEqual(2, tiers["Tier2"]["min_independent_sources"])
        self.assertEqual(15, tiers["Tier3"]["min_authoritative_captures"])
        self.assertEqual(200, tiers["Tier4"]["min_authoritative_captures"])

    def test_docs_embed_generated_trust_tier_block(self) -> None:
        spec = policy_artifacts.load_tier_spec(SPEC_PATH)
        expected_block = policy_artifacts.render_trust_tier_markdown_block(spec)

        for doc_path in (DOC_INDEX, DOC_PIPELINE, DOC_OPS):
            doc_text = doc_path.read_text(encoding="utf-8")
            extracted = policy_artifacts.extract_generated_trust_tier_block(doc_text)
            self.assertEqual(
                expected_block.strip(),
                extracted.strip(),
                msg=f"{doc_path} has tier drift; rerun render_fingerprint_policy_artifacts.py",
            )

    def test_release_evidence_summary_is_generated_and_fail_closed(self) -> None:
        summary = policy_artifacts.load_release_evidence_summary(
            REPO_ROOT / "docs" / "Documentation" / "FINGERPRINT_RELEASE_EVIDENCE_POLICY.generated.json"
        )
        self.assertEqual("reviewed", summary["release_gating_lane"])
        self.assertIn("reviewed_corpus_smoke", summary["required_release_checks"])
        self.assertIn("cxx_stealth_runtime_gate", summary["required_release_checks"])
        self.assertNotIn("imported_corpus_smoke", summary["required_release_checks"])
        self.assertTrue(summary["reviewed_smoke_mandatory"])
        self.assertFalse(summary["imported_lane_release_blocking"])
        self.assertIn("workflow_contract", summary)
        self.assertEqual(
            ".github/workflows/fingerprint-policy-integrity.yml",
            summary["workflow_contract"]["workflow_path"],
        )
        self.assertEqual("reviewed_corpus_smoke", summary["workflow_contract"]["reviewed_job_name"])
        self.assertEqual("imported_corpus_smoke", summary["workflow_contract"]["imported_job_name"])
        self.assertEqual("cxx_stealth_runtime_gate", summary["workflow_contract"]["runtime_gate_job_name"])
        self.assertIn("transport_coherence_status", summary)
        self.assertIn(summary["transport_coherence_status"]["status"], ("pass", "fail", "pending"))
        self.assertTrue(str(summary["transport_coherence_status"]["artifact_path"]).endswith("FINGERPRINT_TRANSPORT_COHERENCE_STATUS.generated.json"))
        self.assertIn(
            "ttl_bucket_match_rate",
            summary["transport_coherence_status"]["required_metrics"],
        )
        if summary["transport_coherence_status"]["status"] == "fail":
            self.assertIn("notes", summary["transport_coherence_status"])
        self.assertIn("active_probing_nightly", summary)
        self.assertEqual("pass", summary["active_probing_nightly"]["status"])
        self.assertTrue(str(summary["active_probing_nightly"]["artifact_path"]).endswith("FINGERPRINT_ACTIVE_PROBING_NIGHTLY_STATUS.generated.json"))


if __name__ == "__main__":
    unittest.main()
