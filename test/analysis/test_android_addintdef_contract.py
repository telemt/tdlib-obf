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
ANDROID_CMAKE_PATH = REPO_ROOT / "example" / "android" / "CMakeLists.txt"
ANDROID_BUILD_SCRIPT_PATH = REPO_ROOT / "example" / "android" / "build-tdlib.sh"
ANDROID_ENV_SCRIPT_PATH = REPO_ROOT / "example" / "android" / "check-environment.sh"
ANDROID_DOCKERFILE_PATH = REPO_ROOT / "example" / "android" / "Dockerfile"
ADD_INT_DEF_SCRIPT_PATH = REPO_ROOT / "example" / "android" / "add_int_def.py"

# Risk test IDs covered by this module:
# - RISK-DOC-02
# - RISK-DOC-03
# - RISK-DOC-04


class AndroidAddIntDefContractTest(unittest.TestCase):
    def test_android_cmake_wires_python_addintdef_contract(self) -> None:
        android_cmake = ANDROID_CMAKE_PATH.read_text(encoding="utf-8")

        self.assertIn(
            "find_package(Python3 REQUIRED COMPONENTS Interpreter)", android_cmake
        )
        self.assertIn("add_int_def.py", android_cmake)
        self.assertIn("${Python3_EXECUTABLE}", android_cmake)
        self.assertIn("${CMAKE_CURRENT_SOURCE_DIR}/add_int_def.py", android_cmake)
        self.assertIn("${TD_API_JAVA_PATH}", android_cmake)
        self.assertNotIn("if (PHP_EXECUTABLE)", android_cmake)
        self.assertNotIn("AddIntDef.php", android_cmake)

    def test_android_shell_and_toolchain_surfaces_require_python3_contract(
        self,
    ) -> None:
        build_script = ANDROID_BUILD_SCRIPT_PATH.read_text(encoding="utf-8")
        env_script = ANDROID_ENV_SCRIPT_PATH.read_text(encoding="utf-8")
        dockerfile = ANDROID_DOCKERFILE_PATH.read_text(encoding="utf-8")

        self.assertIn(
            "python3 add_int_def.py org/drinkless/tdlib/TdApi.java", build_script
        )
        self.assertIn(
            "for TOOL_NAME in gperf jar java javadoc make perl python3 sed tar yes unzip",
            env_script,
        )
        self.assertIn("python3", dockerfile)
        self.assertNotIn("php-cli", dockerfile)

    def test_addintdef_python_annotation_output_contract(self) -> None:
        self.assertTrue(ADD_INT_DEF_SCRIPT_PATH.exists())

        representative_td_api = textwrap.dedent("""
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
            java_path.write_text(representative_td_api + "\n", encoding="utf-8")

            subprocess.run(
                [sys.executable, str(ADD_INT_DEF_SCRIPT_PATH), str(java_path)],
                check=True,
                capture_output=True,
                text=True,
            )

            rendered_once = java_path.read_text(encoding="utf-8")
            self.assertIn("import androidx.annotation.IntDef;", rendered_once)
            self.assertIn("import java.lang.annotation.Retention;", rendered_once)
            self.assertIn("import java.lang.annotation.RetentionPolicy;", rendered_once)
            self.assertIn("@Retention(RetentionPolicy.SOURCE)", rendered_once)
            self.assertIn("@IntDef({", rendered_once)
            self.assertIn("GetOption.CONSTRUCTOR", rendered_once)
            self.assertIn("public @interface Constructors {}", rendered_once)
            self.assertIn("@Constructors", rendered_once)

            subprocess.run(
                [sys.executable, str(ADD_INT_DEF_SCRIPT_PATH), str(java_path)],
                check=True,
                capture_output=True,
                text=True,
            )
            rendered_twice = java_path.read_text(encoding="utf-8")
            self.assertEqual(
                rendered_once,
                rendered_twice,
                msg="add_int_def.py must remain idempotent on already-annotated TdApi.java",
            )

    def test_migration_guardrail_android_paths_must_not_call_php_addintdef(
        self,
    ) -> None:
        combined_android_surfaces = "\n".join(
            [
                ANDROID_CMAKE_PATH.read_text(encoding="utf-8"),
                ANDROID_BUILD_SCRIPT_PATH.read_text(encoding="utf-8"),
                ANDROID_ENV_SCRIPT_PATH.read_text(encoding="utf-8"),
                ANDROID_DOCKERFILE_PATH.read_text(encoding="utf-8"),
            ]
        )

        self.assertNotIn(
            "AddIntDef.php",
            combined_android_surfaces,
            msg="RISK-DOC-02/RISK-DOC-03: Android supported paths must stop depending on AddIntDef.php",
        )
        self.assertNotIn(
            "php",
            combined_android_surfaces.lower(),
            msg="RISK-DOC-02/RISK-DOC-03: Android supported paths must not require PHP",
        )


if __name__ == "__main__":
    unittest.main()
