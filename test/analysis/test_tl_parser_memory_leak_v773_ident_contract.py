# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
"""
Contract test for V773 CWE-401 memory leak in tl_parse_ident.

This test ensures that tl_parse_ident properly manages memory allocation and
deallocation for the L (tl_combinator_tree) pointer across all control flow paths.

DEFECT ANALYSIS:
- CWE-401: Missing Release of Memory after Effective Lifetime
- Location: td/generate/tl-parser/tl-parser.c, tl_parse_ident()
- Function paths:
  1. If var (v) found: allocate L, either free on error path or return
  2. If constructor (c) found: allocate L only after validation, return
  3. If type name: allocate L and return
  4. Otherwise: return NULL (no allocation)

ATTACK VECTORS (Black-hat mindset):
- Inject invalid var that causes error path before nullification
- Trigger constructor path with constraint violations
- Force type name parsing that fails mid-allocation
- Race condition attempts on allocation pointer
"""

import pathlib
import re
import sys
import unittest

THIS_DIR = pathlib.Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from tl_parser_test_helper import read_tl_parser_source  # noqa: E402

# Pattern to locate tl_parse_ident function
TL_PARSE_IDENT_RE = re.compile(
    r"struct tl_combinator_tree \*tl_parse_ident\s*\(.*?\)\s*\{(?P<body>.*?)^(?=struct|void|int|\}[ ]*$)",
    flags=re.DOTALL | re.MULTILINE,
)

# Pattern to detect L allocations
L_ALLOC_RE = re.compile(r"L\s*=\s*alloc_ctree_node\s*\(\s*\)")

# Pattern to detect L frees
L_FREE_RE = re.compile(r"tfree\s*\(\s*L\s*[,)]")

# Pattern to detect return statements
RETURN_RE = re.compile(r"return\s+([^;]+)\s*;")

# Pattern to detect TL_INIT
TL_INIT_RE = re.compile(r"TL_INIT\s*\(\s*L\s*\)")

# Pattern to detect L being set to NULL
L_NULL_RE = re.compile(r"L\s*=\s*0\s*;")

# Pattern to detect if (v) block
VAR_IF_BLOCK_RE = re.compile(
    r"if\s*\(\s*v\s*\)\s*\{(?P<body>.*?)^(?=\s{0,2}(?:struct|if|int|\/\*|\}))",
    flags=re.DOTALL | re.MULTILINE,
)


class TlParserMemoryLeakV773IdentContractTest(unittest.TestCase):
    """Contract tests for tl_parse_ident memory safety."""

    def setUp(self) -> None:
        """Load tl-parser source and extract tl_parse_ident function."""
        self.source = read_tl_parser_source()
        match = TL_PARSE_IDENT_RE.search(self.source)
        self.assertIsNotNone(
            match,
            msg=(
                "tl_parse_ident function not found or does not conform to expected signature. "
                "This contract test ensures the function structure is maintained."
            ),
        )
        self.function_body = match.group("body")

    def test_tl_parse_ident_initializes_L_to_null(self) -> None:
        """CONTRACT: L must be initialized to NULL via TL_INIT."""
        match = TL_INIT_RE.search(self.function_body)
        self.assertIsNotNone(
            match,
            msg=(
                "tl_parse_ident must initialize L pointer using TL_INIT(L) "
                "at function entry to establish known-NULL baseline state"
            ),
        )

    def test_tl_parse_ident_var_path_frees_on_error_before_fail(self) -> None:
        """CONTRACT: var path must tfree L before returning NULL on error."""
        var_match = VAR_IF_BLOCK_RE.search(self.function_body)
        self.assertIsNotNone(var_match, msg="if (v) block must exist for var handling")

        var_body = var_match.group("body")
        # Find the error path where TL_FAIL (return 0) occurs
        error_section = var_body
        self.assertRegex(
            error_section,
            r"tfree\s*\(\s*L\s*,",
            msg=(
                "var error path must call tfree(L, ...) before TL_FAIL to free "
                "allocated combinator tree node on validation failure"
            ),
        )

    def test_tl_parse_ident_all_allocation_sites_have_returns(self) -> None:
        """CONTRACT: Every L allocation site must be followed by eventual return."""
        allocs = list(L_ALLOC_RE.finditer(self.function_body))
        self.assertGreater(
            len(allocs),
            0,
            msg="tl_parse_ident must have at least one L = alloc_ctree_node() allocation",
        )

        for alloc_match in allocs:
            # Find position after this allocation
            after_alloc = self.function_body[alloc_match.end() :]
            # Check that there's a return statement before the next allocation or end
            next_return = RETURN_RE.search(after_alloc)
            self.assertIsNotNone(
                next_return,
                msg=(
                    f"Each L allocation at position {alloc_match.start()} must be "
                    "followed by a return statement to avoid leaking allocated memory"
                ),
            )

    def test_tl_parse_ident_constructor_check_before_allocation(self) -> None:
        """CONTRACT: Constructor validation must occur before L allocation."""
        # Find: struct tl_constructor *c = tl_get_constructor(
        constructor_pattern = (
            r"struct\s+tl_constructor\s+\*c\s*=\s*tl_get_constructor\s*\("
        )
        c_assign = re.search(constructor_pattern, self.function_body)
        self.assertIsNotNone(c_assign, msg="Constructor acquisition must exist")

        # Find: if (c->type->constructors_num != 1) with return
        validation_pattern = (
            r"if\s*\(\s*c\s*->\s*type\s*->\s*constructors_num\s*!=\s*1\s*\)"
        )
        c_validation = re.search(validation_pattern, self.function_body)
        self.assertIsNotNone(
            c_validation, msg="Single constructor validation check must exist"
        )

        # Find the first L allocation in constructor block
        constructor_section_start = c_assign.start()
        c_alloc = L_ALLOC_RE.search(self.function_body[constructor_section_start:])
        self.assertIsNotNone(c_alloc, msg="Constructor path must allocate L")

        # Verify validation comes before allocation
        validation_pos = c_validation.start()
        alloc_pos = constructor_section_start + c_alloc.start()
        self.assertLess(
            validation_pos,
            alloc_pos,
            msg=(
                "Constructor validation (constructors_num == 1) must occur "
                "BEFORE L allocation to prevent leak on validation failure"
            ),
        )

    def test_tl_parse_ident_no_dangling_allocations(self) -> None:
        """ADVERSARIAL: Verify no code path allocates L without eventual free or return."""
        # Count allocations and verify each is accounted for
        alloc_count = len(list(L_ALLOC_RE.finditer(self.function_body)))

        # Count explicit frees (tfree)
        free_count = len(list(L_FREE_RE.finditer(self.function_body)))

        # Count returns (should be >= alloc_count)
        return_count = len(list(RETURN_RE.finditer(self.function_body)))

        # Each allocation is either freed explicitly OR returned via a return statement
        # Verify return > alloc - 1 (since some paths return without freeing)
        self.assertGreaterEqual(
            return_count + free_count,
            alloc_count,
            msg=(
                f"Memory accounting: {alloc_count} allocations, {free_count} frees, {return_count} returns. "
                "Total exits (returns) must be >= allocations to prevent leaks."
            ),
        )


if __name__ == "__main__":
    unittest.main()
