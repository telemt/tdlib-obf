# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT

import pathlib
import re
import unittest


THIS_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = THIS_DIR.parent.parent
CMAKE_LISTS = REPO_ROOT / "CMakeLists.txt"
ISTREAM_TRANSPORT = REPO_ROOT / "td" / "mtproto" / "IStreamTransport.cpp"


class StealthBuildContractTest(unittest.TestCase):
    def test_stealth_shaping_option_defaults_to_enabled(self) -> None:
        content = CMAKE_LISTS.read_text(encoding="utf-8")

        match = re.search(r"option\(\s*TDLIB_STEALTH_SHAPING\b[^\n]*\b(ON|OFF)\s*\)", content)
        self.assertIsNotNone(match, msg="CMake must declare the TDLIB_STEALTH_SHAPING option.")
        self.assertEqual(
            "ON",
            match.group(1),
            msg="TDLIB_STEALTH_SHAPING must default to ON for MTProto-proxy stealth builds.",
        )

    def test_disabling_stealth_shaping_emits_explicit_warning(self) -> None:
        content = CMAKE_LISTS.read_text(encoding="utf-8")

        self.assertIn(
            "Stealth shaping is disabled",
            content,
            msg="CMake must emit an explicit warning when TDLIB_STEALTH_SHAPING is OFF.",
        )

    def test_tls_emulation_secret_fails_fast_when_stealth_is_compiled_off(self) -> None:
        content = ISTREAM_TRANSPORT.read_text(encoding="utf-8")

        self.assertIn(
            "MTProto TLS-emulation proxy secret requires TDLIB_STEALTH_SHAPING=ON",
            content,
            msg=(
                "Transport factory must fail fast with explicit diagnostics when emulate_tls() is used "
                "while stealth shaping is compiled OFF."
            ),
        )


if __name__ == "__main__":
    unittest.main()
