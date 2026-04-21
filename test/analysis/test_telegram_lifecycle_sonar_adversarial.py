# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT

import unittest

import test_telegram_lifecycle_sonar_contract as contract


class TelegramLifecycleSonarAdversarialTest(unittest.TestCase):
    def test_raw_void_callback_scanner_flags_unsafe_signature(self) -> None:
        probe = """
        void on_pending_updated_dialog_timeout_callback(void *messages_manager_ptr, int64 dialog_id_int);
        """
        findings = contract.find_raw_void_callback_signatures(probe)
        self.assertTrue(findings)

    def test_todo_scanner_flags_unfinished_marker(self) -> None:
        probe = "// TODO flush binlog before saving to database"
        findings = contract.find_todo_markers(probe)
        self.assertEqual(["// TODO"], findings)

    def test_scanners_ignore_hardened_patterns(self) -> None:
        probe = """
        void on_pending_updated_dialog_timeout_callback(MultiTimeout::Data messages_manager_ptr, int64 dialog_id_int);
        // Safety note: database persistence ordering remains intentionally fail-closed here.
        """
        self.assertEqual([], contract.find_raw_void_callback_signatures(probe))
        self.assertEqual([], contract.find_todo_markers(probe))


if __name__ == "__main__":
    unittest.main()
