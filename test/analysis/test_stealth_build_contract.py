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

        match = re.search(
            r"option\(\s*TDLIB_STEALTH_SHAPING\b(?P<body>.*?)\)",
            content,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(
            match, msg="CMake must declare the TDLIB_STEALTH_SHAPING option."
        )

        option_body = match.group("body")
        option_defaults = re.findall(r"\b(ON|OFF)\b", option_body)
        self.assertTrue(
            option_defaults,
            msg="TDLIB_STEALTH_SHAPING option must include an explicit ON/OFF default value.",
        )
        self.assertEqual(
            "ON",
            option_defaults[-1],
            msg="TDLIB_STEALTH_SHAPING must default to ON for MTProto-proxy stealth builds.",
        )

    def test_stealth_shaping_compile_definitions_are_set_for_both_modes(self) -> None:
        content = CMAKE_LISTS.read_text(encoding="utf-8")

        self.assertRegex(
            content,
            re.compile(
                r"if\(TDLIB_STEALTH_SHAPING\)\s*"
                r"add_definitions\(-DTDLIB_STEALTH_SHAPING=1\)\s*"
                r"else\(\)"
                r".*?"
                r"add_definitions\(-DTDLIB_STEALTH_SHAPING=0\)\s*"
                r"endif\(\)",
                flags=re.DOTALL,
            ),
            msg=(
                "CMake must set TDLIB_STEALTH_SHAPING compile definitions for both ON and OFF modes "
                "to keep compile-time behavior deterministic."
            ),
        )

    def test_stealth_sources_are_wired_into_mtproto_build_set(self) -> None:
        content = CMAKE_LISTS.read_text(encoding="utf-8")

        required_sources = (
            "td/mtproto/stealth/StealthTransportDecorator.cpp",
            "td/mtproto/stealth/TlsHelloProfileRegistry.cpp",
            "td/mtproto/stealth/TlsHelloBuilder.cpp",
            "td/mtproto/stealth/TrafficClassifier.cpp",
            "td/mtproto/stealth/StealthRuntimeParams.cpp",
        )

        for source in required_sources:
            with self.subTest(source=source):
                self.assertIn(
                    source,
                    content,
                    msg="Required stealth source must be present in TD_MTPROTO_SOURCE for compilation.",
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
