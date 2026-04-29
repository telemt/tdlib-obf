# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
"""
Integration test for V773 CWE-401 memory leak fixes in tl-parser.c.

This test verifies that the change_value_var function correctly deallocates
memory on all error paths, particularly when recursive calls fail.

DEFECT FIXED:
- V773: Memory leak when change_value_var(O->left, X) returns error
- V773: Memory leak when change_value_var(O->right, X) returns error

ROOT CAUSE:
The change_value_var function recursively calls itself on left and right subtrees.
When these recursive calls return error (NULL/0), the code was returning immediately
without deallocating the parent node O, causing memory leaks.

FIX PATTERN:
Before every `return 0;` on error paths from recursive calls, add:
    O->left = 0;
    O->right = 0;
    tfree(O, sizeof(*O));
    return 0;
"""

import pathlib
import re
import sys
import unittest

THIS_DIR = pathlib.Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from tl_parser_test_helper import read_tl_parser_source  # noqa: E402

# Locate change_value_var function
CHANGE_VALUE_VAR_RE = re.compile(
    r"struct tl_combinator_tree \*change_value_var.*?\{(?P<body>.*?)^(?:struct|int|static)",
    flags=re.DOTALL | re.MULTILINE,
)

# Patterns for recursive call error handling
RECURSIVE_CALL_ERROR_PATTERN_1 = re.compile(
    r"t\s*=\s*change_value_var\s*\(\s*O\s*->\s*left\s*,\s*X\s*\)\s*;.*?if\s*\(\s*!\s*t\s*\)",
    flags=re.DOTALL,
)

RECURSIVE_CALL_ERROR_PATTERN_2 = re.compile(
    r"t\s*=\s*change_value_var\s*\(\s*O\s*->\s*right\s*,\s*X\s*\)\s*;.*?if\s*\(\s*!\s*t\s*\)",
    flags=re.DOTALL,
)

# Pattern for safe deallocation in error path
SAFE_DEALLOC_PATTERN = re.compile(
    r"O\s*->\s*left\s*=\s*0\s*;\s*O\s*->\s*right\s*=\s*0\s*;\s*tfree\s*\(\s*O\s*,\s*sizeof\s*\(\s*\*O\s*\)\s*\)\s*;"
)


class TlParserMemoryLeakV773ChangeValueVarIntegrationTest(unittest.TestCase):
    """Integration tests verifying V773 memory leak fixes in change_value_var."""

    def setUp(self) -> None:
        """Load and parse tl-parser source."""
        self.source = read_tl_parser_source()
        match = CHANGE_VALUE_VAR_RE.search(self.source)
        self.assertIsNotNone(
            match,
            msg="change_value_var function not found or does not match expected structure",
        )
        self.function_body = match.group("body")

    def test_left_recursive_call_error_path_safely_deallocates(self) -> None:
        """INTEGRATION: change_value_var(O->left, X) error path deallocates O."""
        # Find the error handler for left recursive call
        left_error_section = RECURSIVE_CALL_ERROR_PATTERN_1.search(self.function_body)
        self.assertIsNotNone(
            left_error_section,
            msg=(
                "Left recursive call error path not found. Expected: "
                "t = change_value_var(O->left, X); if (!t) { ... }"
            ),
        )

        # Verify deallocation happens
        error_handler = left_error_section.group(0)
        after_error_check = error_handler[error_handler.find("if (!t)") :]

        self.assertRegex(
            after_error_check,
            SAFE_DEALLOC_PATTERN,
            msg=(
                "FIXED V773: Left recursive call error path must deallocate O "
                "before returning. Required pattern: "
                "O->left = 0; O->right = 0; tfree(O, sizeof(*O)); return 0;"
            ),
        )

    def test_right_recursive_call_error_path_safely_deallocates(self) -> None:
        """INTEGRATION: change_value_var(O->right, X) error path deallocates O."""
        # Find the error handler for right recursive call
        right_error_section = RECURSIVE_CALL_ERROR_PATTERN_2.search(self.function_body)
        self.assertIsNotNone(
            right_error_section,
            msg=(
                "Right recursive call error path not found. Expected: "
                "t = change_value_var(O->right, X); if (!t) { ... }"
            ),
        )

        # Verify deallocation happens
        error_handler = right_error_section.group(0)
        after_error_check = error_handler[error_handler.find("if (!t)") :]

        self.assertRegex(
            after_error_check,
            SAFE_DEALLOC_PATTERN,
            msg=(
                "FIXED V773: Right recursive call error path must deallocate O "
                "before returning. Required pattern: "
                "O->left = 0; O->right = 0; tfree(O, sizeof(*O)); return 0;"
            ),
        )

    def test_both_error_paths_follow_same_deallocation_pattern(self) -> None:
        """INTEGRATION: Both left and right error paths use consistent deallocation."""
        left_match = RECURSIVE_CALL_ERROR_PATTERN_1.search(self.function_body)
        right_match = RECURSIVE_CALL_ERROR_PATTERN_2.search(self.function_body)

        self.assertIsNotNone(left_match, msg="Left error path not found")
        self.assertIsNotNone(right_match, msg="Right error path not found")

        # Both should have the safe deallocation pattern
        left_section = left_match.group(0)
        right_section = right_match.group(0)

        left_has_dealloc = SAFE_DEALLOC_PATTERN.search(left_section) is not None
        right_has_dealloc = SAFE_DEALLOC_PATTERN.search(right_section) is not None

        self.assertTrue(
            left_has_dealloc and right_has_dealloc,
            msg=(
                "Both left and right recursive error paths must consistently "
                "deallocate O before returning 0. Asymmetric handling indicates "
                "one path still leaks memory."
            ),
        )

    def test_deallocation_sets_pointers_to_null_before_free(self) -> None:
        """SAFETY: Deallocation must nullify left/right pointers before tfree."""
        # This prevents double-free if O is ever referenced after deallocation
        error_sections = list(
            RECURSIVE_CALL_ERROR_PATTERN_1.finditer(self.function_body)
        )
        error_sections.extend(
            RECURSIVE_CALL_ERROR_PATTERN_2.finditer(self.function_body)
        )

        for error_match in error_sections:
            section = error_match.group(0)
            # Find tfree call
            tfree_pos = section.find("tfree")
            self.assertGreater(tfree_pos, -1, msg="tfree must be called in error path")

            # Verify nullification happens before tfree
            before_tfree = section[:tfree_pos]
            self.assertRegex(
                before_tfree,
                r"O\s*->\s*left\s*=\s*0\s*;",
                msg="O->left must be set to 0 before tfree",
            )
            self.assertRegex(
                before_tfree,
                r"O\s*->\s*right\s*=\s*0\s*;",
                msg="O->right must be set to 0 before tfree",
            )


if __name__ == "__main__":
    unittest.main()
