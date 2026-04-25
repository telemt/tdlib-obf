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
PLAN_PATH = REPO_ROOT / "docs" / "Plans" / "FINGERPRINT_DOCUMENTATION_AND_HARDENING_PLAN_2026-04-25.md"
FINAL_AUDIT_PATH = REPO_ROOT / "docs" / "Plans" / "FINGERPRINT_HARDENING_PLAN_FINAL_AUDIT_2026-04-25.md"
OPS_GUIDE_PATH = REPO_ROOT / "docs" / "Documentation" / "FINGERPRINT_OPERATIONS_GUIDE.md"
TRANSPORT_STATUS_PATH = REPO_ROOT / "docs" / "Documentation" / "FINGERPRINT_TRANSPORT_COHERENCE_STATUS.generated.json"


class FingerprintHardeningPlanContractTest(unittest.TestCase):
    def test_status_and_snapshot_sections_are_not_duplicated(self) -> None:
        text = PLAN_PATH.read_text(encoding="utf-8")

        self.assertEqual(1, text.count("## 11. Status"))
        self.assertEqual(1, text.count("### 12.1 Gate Execution Snapshot (2026-04-25)"))
        self.assertEqual(1, text.count("### 12.2 Workstream Closure Status"))
        self.assertEqual(1, text.count("### 12.3 Mandatory Blockers To Unblock Release"))

    def test_stale_failed_gate_snapshot_is_absent(self) -> None:
        text = PLAN_PATH.read_text(encoding="utf-8")

        self.assertNotIn("reviewed lane not green", text)
        self.assertNotIn("informational lane; non-release", text)
        self.assertIn("reviewed lane green as of 2026-04-25", text)

    def test_final_audit_documents_completed_migration_tracking(self) -> None:
        plan_text = PLAN_PATH.read_text(encoding="utf-8")
        final_audit_text = FINAL_AUDIT_PATH.read_text(encoding="utf-8")
        ops_guide_text = OPS_GUIDE_PATH.read_text(encoding="utf-8")

        self.assertNotIn(
            "migration tracking docs (owner/target date per advisory profile) not completed",
            plan_text,
        )
        self.assertIn("Workstream F", final_audit_text)
        self.assertIn(
            "Migration docs: Owner/target date per advisory profile documented",
            final_audit_text,
        )
        self.assertIn("Safari26_3 |", ops_guide_text)
        self.assertIn("IOS14 |", ops_guide_text)
        self.assertIn("Android11_OkHttp_Advisory |", ops_guide_text)

    def test_final_audit_clears_blocker_five_and_keeps_transport_blocker(self) -> None:
        plan_text = PLAN_PATH.read_text(encoding="utf-8")
        final_audit_text = FINAL_AUDIT_PATH.read_text(encoding="utf-8")

        self.assertIn(
            "complete mandatory blocker item 4 in Section 12.3 before next release branch cut",
            plan_text,
        )
        self.assertNotIn("NICE-TO-HAVE", final_audit_text)
        self.assertIn("Mandatory blockers before release cut", final_audit_text)
        self.assertIn("Active-probing CI nightly wrapper - **MET**", final_audit_text)
        self.assertIn("Transport-coherence thresholds - **NOT MET**", final_audit_text)

    def test_final_audit_transport_metrics_match_generated_status(self) -> None:
        transport_status_text = TRANSPORT_STATUS_PATH.read_text(encoding="utf-8")
        final_audit_text = FINAL_AUDIT_PATH.read_text(encoding="utf-8")

        self.assertIn('"ttl_bucket_match_rate": 0.0', transport_status_text)
        self.assertIn('"syn_option_order_class_match_rate": 0.0', transport_status_text)
        self.assertIn('"first_flight_segmentation_signature_match_rate": 1.0', transport_status_text)

        self.assertNotIn("0.39 vs required 0.85+", final_audit_text)
        self.assertNotIn("0.58 vs required 0.95+", final_audit_text)


if __name__ == "__main__":
    unittest.main()
