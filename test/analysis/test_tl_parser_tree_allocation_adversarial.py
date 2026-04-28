# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT

import pathlib
import sys
import unittest

THIS_DIR = pathlib.Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from tl_parser_test_helper import tree_add_child_body  # noqa: E402


class TlParserTreeAllocationAdversarialTest(unittest.TestCase):
    def test_tree_add_child_no_longer_mutates_size_inside_allocation_expression(
        self,
    ) -> None:
        body = tree_add_child_body()
        self.assertNotIn(
            "(++P->size)",
            body,
            msg="tree_add_child must not publish a larger size before allocation succeeds",
        )

    def test_tree_add_child_rejects_child_count_overflow_before_allocating(
        self,
    ) -> None:
        body = tree_add_child_body()
        self.assertRegex(
            body,
            r"if\s*\(\s*P->size\s*==\s*INT_MAX\s*\)|if\s*\(\s*new_size\s*<=\s*P->size\s*\)",
            msg="tree_add_child must guard against signed overflow before computing the resized buffer length",
        )


if __name__ == "__main__":
    unittest.main()
