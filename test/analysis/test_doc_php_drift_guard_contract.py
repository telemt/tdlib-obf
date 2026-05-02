# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs

from __future__ import annotations

import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SCAN_ROOTS = (
    REPO_ROOT / "td" / "generate",
    REPO_ROOT / "example" / "java",
    REPO_ROOT / "example" / "android",
    REPO_ROOT / "example" / "csharp",
    REPO_ROOT / "example" / "uwp",
)

ALLOWLIST_REFERENCE_FILES: set[str] = set()

LEGACY_GENERATOR_PATHS = (
    REPO_ROOT / "td" / "generate" / "DotnetTlDocumentationGenerator.php",
    REPO_ROOT / "td" / "generate" / "DoxygenTlDocumentationGenerator.php",
    REPO_ROOT / "td" / "generate" / "JavadocTlDocumentationGenerator.php",
    REPO_ROOT / "td" / "generate" / "TlDocumentationGenerator.php",
)

DENYLIST_FILES = (
    REPO_ROOT / "CMakeLists.txt",
    REPO_ROOT / "README.md",
    REPO_ROOT / "docs" / "Documentation" / "API_DOCUMENTATION.md",
    REPO_ROOT / "example" / "java" / "CMakeLists.txt",
    REPO_ROOT / "example" / "android" / "CMakeLists.txt",
    REPO_ROOT / "example" / "android" / "build-tdlib.sh",
    REPO_ROOT / "example" / "android" / "check-environment.sh",
    REPO_ROOT / "example" / "android" / "Dockerfile",
    REPO_ROOT / "example" / "android" / "README.md",
    REPO_ROOT / "example" / "java" / "README.md",
    REPO_ROOT / "example" / "csharp" / "README.md",
    REPO_ROOT / "example" / "uwp" / "README.md",
    REPO_ROOT / "td" / "generate" / "CMakeLists.txt",
)

REFERENCE_PATTERN = re.compile(
    r"\bphp\b|PHP_EXECUTABLE|JavadocTlDocumentationGenerator\.php|"
    r"DotnetTlDocumentationGenerator\.php|AddIntDef\.php|php-cli|php\.exe",
    re.IGNORECASE,
)

DENIED_REFERENCE_PATTERNS = (
    "PHP_EXECUTABLE",
    "JavadocTlDocumentationGenerator.php",
    "DotnetTlDocumentationGenerator.php",
    "AddIntDef.php",
    "php-cli",
    "php.exe",
    "php AddIntDef.php",
    "find_program(PHP_EXECUTABLE",
)

# Risk test IDs covered by this module:
# - RISK-DOC-07


class DocPhpDriftGuardContractTest(unittest.TestCase):
    def _collect_reference_files(self) -> set[str]:
        actual_reference_files: set[str] = set()
        for root in SCAN_ROOTS:
            for file_path in root.rglob("*"):
                if not file_path.is_file():
                    continue
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                if REFERENCE_PATTERN.search(content):
                    actual_reference_files.add(
                        file_path.relative_to(REPO_ROOT).as_posix()
                    )
        return actual_reference_files

    def test_doc_generation_php_reference_allowlist_contract(self) -> None:
        actual_reference_files = self._collect_reference_files()

        self.assertEqual(
            ALLOWLIST_REFERENCE_FILES,
            actual_reference_files,
            msg="RISK-DOC-07: PHP drift allowlist changed; update intentionally with review if this is expected",
        )

    def test_legacy_php_doc_generators_are_deleted_contract(self) -> None:
        for path in LEGACY_GENERATOR_PATHS:
            self.assertFalse(
                path.exists(),
                msg=(
                    "RISK-DOC-07: legacy PHP documentation generators must be deleted "
                    f"from supported repository paths ({path.relative_to(REPO_ROOT)})"
                ),
            )

    def test_doc_generation_php_reference_denylist_contract(self) -> None:
        for denylist_file in DENYLIST_FILES:
            content = denylist_file.read_text(encoding="utf-8")
            for denied_pattern in DENIED_REFERENCE_PATTERNS:
                self.assertNotIn(
                    denied_pattern,
                    content,
                    msg=(
                        f"RISK-DOC-07: unexpected PHP doc-generation dependency reference "
                        f"{denied_pattern!r} in {denylist_file.relative_to(REPO_ROOT)}"
                    ),
                )


if __name__ == "__main__":
    unittest.main()
