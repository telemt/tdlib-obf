# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs

from __future__ import annotations

import pathlib
import subprocess
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
GITIGNORE_PATH = REPO_ROOT / ".gitignore"


class DocsPythonCacheHygieneContractTest(unittest.TestCase):
    def test_docs_generator_paths_have_no_tracked_python_cache_artifacts(self) -> None:
        tracked_files = subprocess.run(
            ["git", "ls-files"],
            check=True,
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        ).stdout.splitlines()

        forbidden_prefixes = (
            "td/generate/__pycache__/",
            "example/android/__pycache__/",
        )
        docs_scoped_prefixes = (
            "td/generate/",
            "example/android/",
        )

        for tracked_path in tracked_files:
            in_docs_scope = any(
                tracked_path.startswith(prefix) for prefix in docs_scoped_prefixes
            )
            if not in_docs_scope:
                continue

            self.assertFalse(
                tracked_path.endswith(".pyc"),
                msg=f"Python bytecode must not be tracked in docs migration paths: {tracked_path}",
            )
            for prefix in forbidden_prefixes:
                self.assertFalse(
                    tracked_path.startswith(prefix),
                    msg=f"Python cache path must not be tracked: {tracked_path}",
                )

    def test_gitignore_ignores_python_cache_artifacts(self) -> None:
        gitignore = GITIGNORE_PATH.read_text(encoding="utf-8")

        self.assertIn("**/__pycache__/", gitignore)
        self.assertIn("**/*.pyc", gitignore)


if __name__ == "__main__":
    unittest.main()
