# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs

from __future__ import annotations

import pathlib
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
JAVA_CMAKE_PATH = REPO_ROOT / "example" / "java" / "CMakeLists.txt"
ANDROID_CMAKE_PATH = REPO_ROOT / "example" / "android" / "CMakeLists.txt"
TD_GENERATE_CMAKE_PATH = REPO_ROOT / "td" / "generate" / "CMakeLists.txt"
JAVA_DOC_PYTHON_GENERATOR_PATH = REPO_ROOT / "td" / "generate" / "javadoc_tl_docs.py"

# Risk test IDs covered by this module:
# - RISK-DOC-07
# - RISK-DOC-12


class JavaDocGeneratorContractTest(unittest.TestCase):
    def test_python_javadoc_generator_exists_and_uses_shared_core_contract(
        self,
    ) -> None:
        self.assertTrue(JAVA_DOC_PYTHON_GENERATOR_PATH.exists())

        generator_source = JAVA_DOC_PYTHON_GENERATOR_PATH.read_text(encoding="utf-8")
        self.assertIn(
            "from tl_doc_core import TlDocumentationGenerator as SharedTlDocumentationGenerator",
            generator_source,
        )
        self.assertIn(
            "class JavadocTlDocumentationGenerator(SharedTlDocumentationGenerator):",
            generator_source,
        )
        self.assertNotIn("class TlDocumentationGenerator:\n", generator_source)

    def test_java_example_uses_python_javadoc_generator_contract(self) -> None:
        java_cmake = JAVA_CMAKE_PATH.read_text(encoding="utf-8")

        self.assertIn(
            "find_package(Python3 REQUIRED COMPONENTS Interpreter)", java_cmake
        )
        self.assertIn("javadoc_tl_docs.py", java_cmake)
        self.assertIn("${Python3_EXECUTABLE}", java_cmake)
        self.assertIn(
            "td/bin/td/generate/javadoc_tl_docs.py",
            java_cmake,
        )
        self.assertNotIn("find_program(PHP_EXECUTABLE php)", java_cmake)
        self.assertNotIn("JavadocTlDocumentationGenerator.php", java_cmake)
        self.assertNotIn("if (PHP_EXECUTABLE)", java_cmake)

    def test_android_example_uses_python_java_doc_tools_contract(self) -> None:
        android_cmake = ANDROID_CMAKE_PATH.read_text(encoding="utf-8")

        self.assertIn(
            "find_package(Python3 REQUIRED COMPONENTS Interpreter)", android_cmake
        )
        self.assertIn("javadoc_tl_docs.py", android_cmake)
        self.assertIn("add_int_def.py", android_cmake)
        self.assertIn("${Python3_EXECUTABLE}", android_cmake)
        self.assertNotIn("JavadocTlDocumentationGenerator.php", android_cmake)
        self.assertNotIn("if (PHP_EXECUTABLE)", android_cmake)
        self.assertNotIn("AddIntDef.php", android_cmake)

    def test_jni_install_surface_ships_python_generators_contract(self) -> None:
        td_generate_cmake = TD_GENERATE_CMAKE_PATH.read_text(encoding="utf-8")

        self.assertIn(
            "install(FILES javadoc_tl_docs.py dotnet_tl_docs.py tl_doc_core.py",
            td_generate_cmake,
        )
        self.assertIn(
            'DESTINATION "${CMAKE_INSTALL_BINDIR}/td/generate"',
            td_generate_cmake,
        )
        self.assertNotIn("JavadocTlDocumentationGenerator.php", td_generate_cmake)
        self.assertNotIn("TlDocumentationGenerator.php", td_generate_cmake)

    def test_migration_guardrail_java_paths_must_stop_referencing_php_generator(
        self,
    ) -> None:
        combined_java_surfaces = "\n".join(
            [
                JAVA_CMAKE_PATH.read_text(encoding="utf-8"),
                ANDROID_CMAKE_PATH.read_text(encoding="utf-8"),
                TD_GENERATE_CMAKE_PATH.read_text(encoding="utf-8"),
            ]
        )

        self.assertNotIn(
            "PHP_EXECUTABLE",
            combined_java_surfaces,
            msg="RISK-DOC-12: Java/JNI supported surfaces must not rely on PHP discovery",
        )
        self.assertNotIn(
            "JavadocTlDocumentationGenerator.php",
            combined_java_surfaces,
            msg="RISK-DOC-12: Java/JNI supported surfaces must stop depending on the PHP Javadoc generator",
        )
        self.assertNotIn(
            "AddIntDef.php",
            combined_java_surfaces,
            msg="RISK-DOC-12: Java/Android supported surfaces must stop depending on PHP AddIntDef",
        )


if __name__ == "__main__":
    unittest.main()
