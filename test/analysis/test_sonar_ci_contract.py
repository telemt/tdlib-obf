# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT

import pathlib
import unittest


THIS_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = THIS_DIR.parent.parent
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "sonar.yml"


class SonarCiContractTest(unittest.TestCase):
    def test_workflow_limits_triggers_to_analysis_relevant_paths(self) -> None:
        workflow_text = WORKFLOW_PATH.read_text(encoding="utf-8")

        self.assertIn("pull_request:", workflow_text)
        self.assertIn("paths:", workflow_text)
        self.assertIn("'**/*.cpp'", workflow_text)
        self.assertIn("'**/*.h'", workflow_text)
        self.assertIn("'**/CMakeLists.txt'", workflow_text)
        self.assertIn("'CMake/**'", workflow_text)
        self.assertIn("'sonar-project.properties'", workflow_text)

    def test_workflow_uses_compile_commands_instead_of_build_wrapper(self) -> None:
        workflow_text = WORKFLOW_PATH.read_text(encoding="utf-8")

        self.assertNotIn("install-build-wrapper", workflow_text)
        self.assertNotIn("build-wrapper-linux-x86-64", workflow_text)
        self.assertIn("-DCMAKE_EXPORT_COMPILE_COMMANDS=ON", workflow_text)
        self.assertIn("-Dsonar.cfamily.compile-commands=build/compile_commands.json", workflow_text)

    def test_workflow_builds_generation_targets_only_for_analysis_inputs(self) -> None:
        workflow_text = WORKFLOW_PATH.read_text(encoding="utf-8")

        self.assertIn(
            "cmake --build build --target tl_generate_tlo tl_generate_mtproto tl_generate_common tl_generate_json tdmime_auto",
            workflow_text,
        )
        self.assertNotIn("cmake --build build --target install", workflow_text)

    def test_workflow_disables_target_pch_for_compile_commands_stability(self) -> None:
        workflow_text = WORKFLOW_PATH.read_text(encoding="utf-8")

        self.assertIn(
            "-DTD_ENABLE_TARGET_PCH=OFF",
            workflow_text,
            msg="Sonar compile_commands flow must disable target PCH to avoid references to missing cmake_pch.hxx.pch artifacts",
        )


if __name__ == "__main__":
    unittest.main()
