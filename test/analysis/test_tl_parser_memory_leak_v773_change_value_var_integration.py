# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
"""Integration test for the tagged-result change_value_var ownership fix."""

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
    r"struct tl_tree_change_result\s+change_value_var.*?\{(?P<body>.*?)^(?:struct|int|static)",
    flags=re.DOTALL | re.MULTILINE,
)

# Patterns for recursive call error handling
RECURSIVE_CALL_ERROR_PATTERN_1 = re.compile(
    r"t\s*=\s*change_value_var\s*\(\s*O\s*->\s*left\s*,\s*X\s*\)\s*;\s*"
    r"if\s*\(\s*tl_tree_change_is_error\s*\(\s*t\s*\)\s*\)\s*\{(?P<body>.*?)\}",
    flags=re.DOTALL,
)

RECURSIVE_CALL_ERROR_PATTERN_2 = re.compile(
    r"t\s*=\s*change_value_var\s*\(\s*O\s*->\s*right\s*,\s*X\s*\)\s*;\s*"
    r"if\s*\(\s*tl_tree_change_is_error\s*\(\s*t\s*\)\s*\)\s*\{(?P<body>.*?)\}",
    flags=re.DOTALL,
)

# Pattern for safe deallocation in error path
SAFE_DEALLOC_PATTERN = re.compile(
    r"O\s*->\s*left\s*=\s*0\s*;\s*O\s*->\s*right\s*=\s*0\s*;\s*tfree\s*\(\s*O\s*,\s*sizeof\s*\(\s*\*O\s*\)\s*\)\s*;\s*return\s+tl_tree_change_make_error\s*\(\s*\)\s*;"
)


class TlParserMemoryLeakV773ChangeValueVarIntegrationTest(unittest.TestCase):
    """Integration tests verifying tagged-result change_value_var ownership paths."""

    def setUp(self) -> None:
        """Load and parse tl-parser source."""
        self.source = read_tl_parser_source()
        match = CHANGE_VALUE_VAR_RE.search(self.source)
        self.assertIsNotNone(
            match,
            msg=(
                "change_value_var function not found or does not match the "
                "expected tagged-result structure"
            ),
        )
        self.function_body = match.group("body")

    def test_change_value_var_uses_tagged_result_signature(self) -> None:
        """CONTRACT: change_value_var must return a tagged result."""
        self.assertIn(
            "struct tl_tree_change_result change_value_var",
            self.source,
            msg=(
                "change_value_var must return struct tl_tree_change_result so "
                "callers do not encode control flow in raw pointer sentinels"
            ),
        )

    def test_left_recursive_call_error_path_safely_deallocates(self) -> None:
        """INTEGRATION: change_value_var(O->left, X) error path deallocates O."""
        # Find the error handler for left recursive call
        left_error_section = RECURSIVE_CALL_ERROR_PATTERN_1.search(self.function_body)
        self.assertIsNotNone(
            left_error_section,
            msg=(
                "Left recursive call error path not found. Expected: "
                "t = change_value_var(O->left, X); "
                "if (tl_tree_change_is_error(t)) { ... }"
            ),
        )

        # Verify deallocation happens
        error_handler = left_error_section.group("body")

        self.assertRegex(
            error_handler,
            SAFE_DEALLOC_PATTERN,
            msg=(
                "FIXED V773: Left recursive call error path must deallocate O "
                "before returning. Required pattern: "
                "O->left = 0; O->right = 0; tfree(O, sizeof(*O)); "
                "return tl_tree_change_make_error();"
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
                "t = change_value_var(O->right, X); "
                "if (tl_tree_change_is_error(t)) { ... }"
            ),
        )

        # Verify deallocation happens
        error_handler = right_error_section.group("body")

        self.assertRegex(
            error_handler,
            SAFE_DEALLOC_PATTERN,
            msg=(
                "FIXED V773: Right recursive call error path must deallocate O "
                "before returning. Required pattern: "
                "O->left = 0; O->right = 0; tfree(O, sizeof(*O)); "
                "return tl_tree_change_make_error();"
            ),
        )

    def test_both_error_paths_follow_same_deallocation_pattern(self) -> None:
        """INTEGRATION: Both left and right error paths use consistent deallocation."""
        left_match = RECURSIVE_CALL_ERROR_PATTERN_1.search(self.function_body)
        right_match = RECURSIVE_CALL_ERROR_PATTERN_2.search(self.function_body)

        self.assertIsNotNone(left_match, msg="Left error path not found")
        self.assertIsNotNone(right_match, msg="Right error path not found")

        # Both should have the safe deallocation pattern
        left_section = left_match.group("body")
        right_section = right_match.group("body")

        left_has_dealloc = SAFE_DEALLOC_PATTERN.search(left_section) is not None
        right_has_dealloc = SAFE_DEALLOC_PATTERN.search(right_section) is not None

        self.assertTrue(
            left_has_dealloc and right_has_dealloc,
            msg=(
                "Both left and right recursive error paths must consistently "
                "deallocate O before returning an error result. Asymmetric handling indicates "
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
            section = error_match.group("body")
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
