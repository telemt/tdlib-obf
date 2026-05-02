# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs

import pathlib
import re
import unittest

THIS_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = THIS_DIR.parent.parent
ROOT_CMAKE_PATH = REPO_ROOT / "CMakeLists.txt"


class ZlibMinimumVersionContractTest(unittest.TestCase):
    def test_root_cmake_declares_minimum_supported_zlib_version(self) -> None:
        root_cmake = ROOT_CMAKE_PATH.read_text(encoding="utf-8")

        self.assertIn(
            'set(TD_ZLIB_MIN_VERSION "1.3.2")',
            root_cmake,
            msg="root CMake must pin a minimum zlib version to prevent vulnerable builds",
        )
        self.assertRegex(
            root_cmake,
            r"if\s*\(\s*TD_ZLIB_VERSION\s+VERSION_LESS\s+TD_ZLIB_MIN_VERSION\s*\)",
            msg="root CMake must compare discovered zlib version against the configured minimum",
        )

    def test_root_cmake_rejects_unknown_or_old_zlib_versions(self) -> None:
        root_cmake = ROOT_CMAKE_PATH.read_text(encoding="utf-8")

        self.assertIn(
            "Unable to determine zlib version from CMake discovery",
            root_cmake,
            msg="root CMake must fail closed if zlib version cannot be determined",
        )
        self.assertRegex(
            root_cmake,
            re.escape(
                "zlib ${TD_ZLIB_VERSION} is too old. Minimum supported version is ${TD_ZLIB_MIN_VERSION}."
            ),
            msg="root CMake must reject zlib versions lower than the configured minimum",
        )

    def test_root_cmake_has_header_parsing_fallback_for_zlib_version(self) -> None:
        root_cmake = ROOT_CMAKE_PATH.read_text(encoding="utf-8")

        self.assertIn(
            "ZLIB_VERSION_STRING",
            root_cmake,
            msg="root CMake must use CMake-provided zlib version metadata when available",
        )
        self.assertIn(
            'file(STRINGS "${ZLIB_INCLUDE_DIR}/zlib.h" TD_ZLIB_VERSION_LINE',
            root_cmake,
            msg="root CMake must parse zlib.h as a fallback when module version metadata is missing",
        )


if __name__ == "__main__":
    unittest.main()
