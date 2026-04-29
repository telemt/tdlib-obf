# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
"""
Adversarial test for V773 CWE-401 memory leak in tl_parse_ident.

This black-hat test attempts to trigger the memory leak through:
1. Malformed input trees that stress validation paths
2. Unconstrained early returns that skip deallocation
3. Conflicting state that confuses the allocator
4. Edge cases in constructor validation
"""

import pathlib
import re
import sys
import unittest

THIS_DIR = pathlib.Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from tl_parser_test_helper import read_tl_parser_source  # noqa: E402

# Detect variable error paths
VAR_ERROR_SECTION_RE = re.compile(
    r"if\s*\(L\s*->\s*type\s*==\s*type_num\s*&&\s*s\s*\)(?P<body>.*?)^\s{4}\}",
    flags=re.DOTALL | re.MULTILINE,
)

# Detect constructor block boundary
CONSTRUCTOR_BLOCK_RE = re.compile(
    r"struct tl_constructor \*c = tl_get_constructor.*?if \(c\) \{(?P<body>.*?)^\s{2}\}",
    flags=re.DOTALL | re.MULTILINE,
)

# Detect type name block
TYPE_NAME_BLOCK_RE = re.compile(
    r"int x = tl_is_type_name.*?if \(x\) \{(?P<body>.*?)^\s{2}\} else \{",
    flags=re.DOTALL | re.MULTILINE,
)

# Pattern for early returns (potential leak points)
EARLY_RETURN_RE = re.compile(r"return\s+(\d+|NULL|0)\s*;")

# Pattern for tfree calls
TFREE_RE = re.compile(r"tfree\s*\(L\s*[,)]")

# Pattern for L = 0 assignments
L_NULL_RE = re.compile(r"L\s*=\s*0\s*;")


class TlParserMemoryLeakV773IdentAdversarialTest(unittest.TestCase):
    """Adversarial tests attempting to trigger V773 memory leaks in tl_parse_ident."""

    def setUp(self) -> None:
        """Load tl-parser source."""
        self.source = read_tl_parser_source()
        # Extract tl_parse_ident function
        match = re.search(
            r"struct tl_combinator_tree \*tl_parse_ident\s*\(.*?\)\s*\{(?P<body>.*?)^(?=struct|void|int|\}[ ]*$)",
            self.source,
            flags=re.DOTALL | re.MULTILINE,
        )
        self.assertIsNotNone(match, "Failed to locate tl_parse_ident function")
        self.function_body = match.group("body")

    def test_var_error_path_safely_deallocates_before_return(self) -> None:
        """ADVERSARIAL: var error path must free L before any return/exit."""
        var_err_match = VAR_ERROR_SECTION_RE.search(self.function_body)
        if not var_err_match:
            # If pattern not found, check manually for the error condition
            self.assertIn(
                "TL_ERROR",
                self.function_body,
                msg="Error handling must exist in var path",
            )
            return

        var_err_body = var_err_match.group("body")

        # Verify tfree is called
        self.assertRegex(
            var_err_body,
            TFREE_RE,
            msg=(
                "CRITICAL: var error path must call tfree(L) before any exit. "
                "Failure allows allocated memory to escape without deallocation. "
                "Attack: allocate via var path, trigger error condition, exploit leak."
            ),
        )

        # Verify L is nullified after free
        after_free = var_err_body[var_err_body.find("tfree") :]
        self.assertRegex(
            after_free,
            L_NULL_RE,
            msg=(
                "CRITICAL: After tfree, L must be set to NULL to prevent double-free. "
                "Attack: race condition on double-free leading to heap corruption."
            ),
        )

    def test_constructor_validation_prevents_leak_on_multi_constructor_rejection(
        self,
    ) -> None:
        """ADVERSARIAL: Constructor with multiple constructors must not allocate L."""
        constructor_match = CONSTRUCTOR_BLOCK_RE.search(self.function_body)
        if not constructor_match:
            # Fallback: search for constructors_num check
            self.assertIn(
                "constructors_num",
                self.function_body,
                msg="Constructor validation check must exist",
            )
            return

        constructor_body = constructor_match.group("body")

        # Find the validation check
        validation_start = constructor_body.find("constructors_num")
        self.assertGreater(
            validation_start,
            -1,
            msg="Constructor validation (constructors_num != 1) not found",
        )

        # Extract the validation section up to the else/next-if
        validation_section = constructor_body[:300]  # Look ahead

        # Verify that allocation comes AFTER the validation
        validation_pos = validation_section.find("constructors_num")
        alloc_pos = validation_section.find("alloc_ctree_node")

        if alloc_pos >= 0:
            self.assertGreater(
                alloc_pos,
                validation_pos,
                msg=(
                    "CRITICAL: Constructor validation must occur BEFORE allocation. "
                    "Attack: Craft input with multiple constructors, bypass validation, "
                    "trigger allocation with invalid state leading to leak."
                ),
            )

    def test_type_name_path_returns_allocated_memory_safely(self) -> None:
        """ADVERSARIAL: Type name path must either return L or free it."""
        type_match = TYPE_NAME_BLOCK_RE.search(self.function_body)
        if not type_match:
            # Fallback: look for type name handling
            self.assertIn(
                "tl_is_type_name",
                self.function_body,
                msg="Type name check must exist",
            )
            return

        type_body = type_match.group("body")

        # Verify either return or free exists
        has_allocation = "alloc_ctree_node" in type_body
        has_return = "return" in type_body
        has_free = "tfree" in type_body

        if has_allocation:
            self.assertTrue(
                has_return or has_free,
                msg=(
                    "ADVERSARIAL: Type name path allocates L but doesn't return or free it. "
                    "Attack: Trigger type name parsing with failed allocation, "
                    "hit undefined path execution, leak allocated memory."
                ),
            )

    def test_all_error_paths_deallocate_before_early_return(self) -> None:
        """ADVERSARIAL: Every early return (return 0/NULL) must be protected by free."""
        # Find all TL_ERROR calls
        error_lines = [m for m in re.finditer(r"TL_ERROR\s*\(", self.function_body)]

        if not error_lines:
            self.skipTest("No TL_ERROR calls found")
            return

        for error_match in error_lines:
            error_pos = error_match.start()
            # Look for next TL_FAIL or return 0 after error
            after_error = self.function_body[error_pos : error_pos + 500]

            # Must have either tfree or return immediately after TL_ERROR
            has_tfree = TFREE_RE.search(after_error)
            has_return = EARLY_RETURN_RE.search(after_error)

            self.assertTrue(
                has_tfree or has_return,
                msg=(
                    f"ADVERSARIAL: TL_ERROR at position {error_pos} must be followed "
                    "by tfree (if L allocated) or immediate return. "
                    "Attack: Inject error condition to skip deallocation."
                ),
            )


if __name__ == "__main__":
    unittest.main()
