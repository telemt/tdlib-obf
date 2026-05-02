# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs

from __future__ import annotations

import hashlib
import pathlib
import subprocess
import sys
import tempfile
import textwrap
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
TD_API_TL_PATH = REPO_ROOT / "td" / "generate" / "scheme" / "td_api.tl"
DOTNET_PYTHON_GENERATOR_PATH = REPO_ROOT / "td" / "generate" / "dotnet_tl_docs.py"
ANDROID_ADD_INT_DEF_PYTHON_PATH = REPO_ROOT / "example" / "android" / "add_int_def.py"


class PythonDocGeneratorsStressTest(unittest.TestCase):
    def test_dotnet_xml_generation_is_deterministic_under_repeated_runs(self) -> None:
        self.assertTrue(DOTNET_PYTHON_GENERATOR_PATH.exists())

        digests: set[str] = set()
        with tempfile.TemporaryDirectory() as tmp_dir:
            xml_output = pathlib.Path(tmp_dir) / "Telegram.Td.xml"
            for _ in range(30):
                subprocess.run(
                    [
                        sys.executable,
                        str(DOTNET_PYTHON_GENERATOR_PATH),
                        str(TD_API_TL_PATH),
                        str(xml_output),
                        "Windows",
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                digest = hashlib.sha256(xml_output.read_bytes()).hexdigest()
                digests.add(digest)

        self.assertEqual(
            1,
            len(digests),
            msg="dotnet_tl_docs.py output must be deterministic across repeated runs",
        )

    def test_add_int_def_python_is_idempotent_under_repeated_runs(self) -> None:
        self.assertTrue(ANDROID_ADD_INT_DEF_PYTHON_PATH.exists())

        source = textwrap.dedent("""
            package org.drinkless.tdlib;

            import androidx.annotation.Nullable;

            public final class TdApi {
                public abstract static class Object extends Object {
                    @Override
                    public abstract int getConstructor();
                }

                public abstract static class Function<R extends Object> extends Object {
                    @Override
                    public abstract int getConstructor();
                }

                public static class UpdateNewMessage extends Object {
                    public static final int CONSTRUCTOR = 0x01020304;

                    @Override
                    public int getConstructor() {
                        return CONSTRUCTOR;
                    }
                }

                public static class GetOption extends Function {
                    public static final int CONSTRUCTOR = 0x0A0B0C0D;

                    @Override
                    public int getConstructor() {
                        return CONSTRUCTOR;
                    }
                }
            }
            """).strip()

        with tempfile.TemporaryDirectory() as tmp_dir:
            java_path = pathlib.Path(tmp_dir) / "TdApi.java"
            java_path.write_text(source + "\n", encoding="utf-8")

            baseline_digest = ""
            for index in range(30):
                subprocess.run(
                    [
                        sys.executable,
                        str(ANDROID_ADD_INT_DEF_PYTHON_PATH),
                        str(java_path),
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                digest = hashlib.sha256(java_path.read_bytes()).hexdigest()
                if index == 0:
                    baseline_digest = digest
                self.assertEqual(
                    baseline_digest,
                    digest,
                    msg="add_int_def.py output must remain stable after first application",
                )


if __name__ == "__main__":
    unittest.main()
