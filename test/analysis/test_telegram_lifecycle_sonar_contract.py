# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT

import pathlib
import re
import unittest


THIS_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = THIS_DIR.parent.parent

MESSAGES_LIFECYCLE_PATH = REPO_ROOT / "td" / "telegram" / "MessagesManagerLifecycle.cpp"
STORY_LIFECYCLE_PATH = REPO_ROOT / "td" / "telegram" / "StoryManagerLifecycle.cpp"
MESSAGES_HEADER_PATH = REPO_ROOT / "td" / "telegram" / "MessagesManager.h"
STORY_HEADER_PATH = REPO_ROOT / "td" / "telegram" / "StoryManager.h"
TL_STORERS_PATH = REPO_ROOT / "tdutils" / "td" / "utils" / "tl_storers.h"

RAW_VOID_CALLBACK_PATTERN = re.compile(
    r"on_[A-Za-z0-9_]+_timeout_callback\s*\(\s*void\s*\*",
    re.MULTILINE,
)
TODO_PATTERN = re.compile(r"//\s*TODO\b", re.MULTILINE)


def find_raw_void_callback_signatures(text: str) -> list[str]:
    return [match.group(0) for match in RAW_VOID_CALLBACK_PATTERN.finditer(text)]


def find_todo_markers(text: str) -> list[str]:
    return [match.group(0) for match in TODO_PATTERN.finditer(text)]


class TelegramLifecycleSonarContractTest(unittest.TestCase):
    def test_lifecycle_callbacks_do_not_use_raw_void_pointer_signatures(self) -> None:
        targets = (
            MESSAGES_LIFECYCLE_PATH,
            STORY_LIFECYCLE_PATH,
            MESSAGES_HEADER_PATH,
            STORY_HEADER_PATH,
        )
        violations: list[str] = []

        for path in targets:
            findings = find_raw_void_callback_signatures(path.read_text(encoding="utf-8"))
            if findings:
                rel = path.relative_to(REPO_ROOT).as_posix()
                violations.append(f"{rel}: {findings}")

        self.assertEqual(
            [],
            violations,
            msg="lifecycle callbacks must not expose raw void* signatures",
        )

    def test_lifecycle_files_do_not_contain_todo_markers(self) -> None:
        targets = (MESSAGES_LIFECYCLE_PATH, STORY_LIFECYCLE_PATH)
        violations: list[str] = []

        for path in targets:
            findings = find_todo_markers(path.read_text(encoding="utf-8"))
            if findings:
                rel = path.relative_to(REPO_ROOT).as_posix()
                violations.append(f"{rel}: {findings}")

        self.assertEqual([], violations, msg="lifecycle implementation must not ship TODO markers")

    def test_messages_lifecycle_uses_const_group_key_iteration(self) -> None:
        source = MESSAGES_LIFECYCLE_PATH.read_text(encoding="utf-8")
        self.assertIn("for (const auto &group_key : changed_group_keys)", source)

    def test_messages_lifecycle_uses_to_underlying_for_enum_index(self) -> None:
        source = MESSAGES_LIFECYCLE_PATH.read_text(encoding="utf-8")
        self.assertIn("std::to_underlying(MessageSearchFilter::Call)", source)

    def test_messages_lifecycle_uses_enum_import_for_filter_masks(self) -> None:
        source = MESSAGES_LIFECYCLE_PATH.read_text(encoding="utf-8")
        self.assertIn("using enum MessageSearchFilter;", source)

    def test_story_lifecycle_uses_if_init_statement_for_story_lookup(self) -> None:
        source = STORY_LIFECYCLE_PATH.read_text(encoding="utf-8")
        self.assertIn("if (auto story = get_story(story_full_id);", source)

    def test_story_lifecycle_avoids_move_into_const_ref_consumers(self) -> None:
        source = STORY_LIFECYCLE_PATH.read_text(encoding="utf-8")
        self.assertNotIn("std::move(database_story.data_)", source)

    def test_tl_storers_uses_variable_template_trait_check(self) -> None:
        source = TL_STORERS_PATH.read_text(encoding="utf-8")
        self.assertIn("std::is_trivially_copyable_v<T>", source)


if __name__ == "__main__":
    unittest.main()
