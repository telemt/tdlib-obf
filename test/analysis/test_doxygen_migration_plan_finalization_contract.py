# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs

from __future__ import annotations

import pathlib
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
PLAN_PATH = (
    REPO_ROOT / "docs" / "Plans" / "DOXYGEN_COMPLETE_MIGRATION_PLAN_2026-05-02.md"
)


class DoxygenMigrationPlanFinalizationContractTest(unittest.TestCase):
    def test_plan_declares_finalized_status_contract(self) -> None:
        plan = PLAN_PATH.read_text(encoding="utf-8")

        self.assertIn("**Status:** Finalized", plan)
        self.assertIn("Finalization Record", plan)

    def test_plan_uses_operational_follow_up_not_open_closure_tasks_contract(
        self,
    ) -> None:
        plan = PLAN_PATH.read_text(encoding="utf-8")

        self.assertIn("Operational Follow-Up (Non-Blocking)", plan)
        self.assertNotIn("Remaining closure tasks:", plan)


if __name__ == "__main__":
    unittest.main()
