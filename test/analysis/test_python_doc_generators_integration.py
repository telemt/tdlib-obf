# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs

from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile
import textwrap
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
TD_API_TL_PATH = REPO_ROOT / "td" / "generate" / "scheme" / "td_api.tl"
JAVADOC_PYTHON_GENERATOR_PATH = REPO_ROOT / "td" / "generate" / "javadoc_tl_docs.py"
DOTNET_PYTHON_GENERATOR_PATH = REPO_ROOT / "td" / "generate" / "dotnet_tl_docs.py"
ANDROID_ADD_INT_DEF_PYTHON_PATH = REPO_ROOT / "example" / "android" / "add_int_def.py"


class PythonDocGeneratorsIntegrationTest(unittest.TestCase):
    def _representative_td_api_java_source(self) -> str:
        return textwrap.dedent("""
            package org.drinkless.tdlib;

            import androidx.annotation.Nullable;

            public class TdApi {
                public abstract static class Object {
                    public Object() {
                    }

                    public abstract int getConstructor();

                    public native String toString();
                }

                public abstract static class Function<R extends Object> extends Object {
                    public Function() {
                    }

                    public static final int CONSTRUCTOR = 0x00000000;

                    @Override
                    public int getConstructor() {
                        return CONSTRUCTOR;
                    }
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

    def test_java_doc_and_android_intdef_python_pipeline_integration(self) -> None:
        self.assertTrue(JAVADOC_PYTHON_GENERATOR_PATH.exists())
        self.assertTrue(ANDROID_ADD_INT_DEF_PYTHON_PATH.exists())

        with tempfile.TemporaryDirectory() as tmp_dir:
            java_path = pathlib.Path(tmp_dir) / "TdApi.java"
            java_path.write_text(
                self._representative_td_api_java_source() + "\n", encoding="utf-8"
            )

            subprocess.run(
                [
                    sys.executable,
                    str(JAVADOC_PYTHON_GENERATOR_PATH),
                    str(TD_API_TL_PATH),
                    str(java_path),
                    "androidx.annotation.Nullable",
                    "@Nullable",
                    "8",
                ],
                check=True,
                capture_output=True,
                text=True,
            )

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

            rendered = java_path.read_text(encoding="utf-8")
            self.assertIn(
                "This class contains as static nested classes all other TDLib interface",
                rendered,
            )
            self.assertIn("public @interface Constructors {}", rendered)
            self.assertIn("@Constructors", rendered)
            self.assertIn("GetOption.CONSTRUCTOR", rendered)

    def test_dotnet_python_generator_integration_contract(self) -> None:
        self.assertTrue(DOTNET_PYTHON_GENERATOR_PATH.exists())

        with tempfile.TemporaryDirectory() as tmp_dir:
            xml_output = pathlib.Path(tmp_dir) / "Telegram.Td.xml"
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

            rendered = xml_output.read_text(encoding="utf-8")
            self.assertIn('<?xml version="1.0"?>', rendered)
            self.assertIn('<member name="T:Telegram.Td.Api.Object">', rendered)
            self.assertIn('<member name="T:Telegram.Td.Client">', rendered)
            self.assertIn(
                '<member name="M:Telegram.Td.Client.Create(Telegram.Td.ClientResultHandler)">',
                rendered,
            )
            self.assertIn("</doc>", rendered)


if __name__ == "__main__":
    unittest.main()
