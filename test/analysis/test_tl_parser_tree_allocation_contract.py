# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT

import pathlib
import sys
import unittest

THIS_DIR = pathlib.Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from tl_parser_test_helper import find_guard_offset, tree_add_child_body  # noqa: E402


class TlParserTreeAllocationContractTest(unittest.TestCase):
    def test_tree_add_child_checks_allocated_buffer_before_memcpy(self) -> None:
        body = tree_add_child_body()
        memcpy_offset = body.find("memcpy(")
        self.assertGreaterEqual(
            memcpy_offset, 0, msg="tree_add_child must keep copying existing children"
        )

        guard_offset = find_guard_offset(body)
        self.assertGreaterEqual(
            guard_offset,
            0,
            msg="tree_add_child must check the new child buffer pointer before copying prior children",
        )
        self.assertLess(
            guard_offset,
            memcpy_offset,
            msg="tree_add_child must reject allocation failure before memcpy can dereference the new buffer",
        )

    def test_tree_add_child_uses_fail_closed_allocation_error_path(self) -> None:
        body = tree_add_child_body()
        guard_offset = find_guard_offset(body)
        self.assertGreaterEqual(guard_offset, 0)
        self.assertRegex(
            body[guard_offset:],
            r"tl_parser_fatal_allocation_error\s*\(|abort\s*\(",
            msg=(
                "tree_add_child must fail closed by delegating to the parser allocation-failure handler "
                "or aborting directly when growing the child buffer fails"
            ),
        )


if __name__ == "__main__":
    unittest.main()
