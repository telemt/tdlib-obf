# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs

from __future__ import annotations

import contextlib
import io
import pathlib
import subprocess
import sys
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
GENERATE_DIR = REPO_ROOT / "td" / "generate"
ANDROID_ADD_INT_DEF_PYTHON_PATH = REPO_ROOT / "example" / "android" / "add_int_def.py"

sys.path.insert(0, str(GENERATE_DIR))
from dotnet_tl_docs import DotnetTlDocumentationGenerator  # noqa: E402
from javadoc_tl_docs import JavadocTlDocumentationGenerator  # noqa: E402


class PythonDocGeneratorsAdversarialTest(unittest.TestCase):
    def test_javadoc_escape_neutralizes_comment_close_and_html_injection(self) -> None:
        generator = JavadocTlDocumentationGenerator("", "", 8)
        payload = 'Break */ <script>alert("x")</script> test_case'

        escaped = generator.escape_documentation(payload)

        self.assertNotIn("*/", escaped)
        self.assertIn("*&#47;", escaped)
        self.assertIn("&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;", escaped)
        self.assertIn("testCase", escaped)

    def test_dotnet_escape_neutralizes_comment_close_and_xml_injection(self) -> None:
        generator = DotnetTlDocumentationGenerator("Windows")
        payload = 'Break */ <tag attr="x">payload</tag> test_case'

        escaped = generator.escape_documentation(payload)

        self.assertNotIn("*/", escaped)
        self.assertIn("*&#47;", escaped)
        self.assertIn("&lt;tag attr=&quot;x&quot;&gt;payload&lt;/tag&gt;", escaped)
        self.assertIn("TestCase", escaped)

    def test_malformed_vector_type_fails_closed(self) -> None:
        javadoc_generator = JavadocTlDocumentationGenerator("", "", 8)
        dotnet_generator = DotnetTlDocumentationGenerator("Windows")

        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual("", javadoc_generator.get_type_name("vector<int32"))
            self.assertEqual("", dotnet_generator.get_type_name("vector<int32"))

    def test_add_int_def_cli_rejects_missing_argument(self) -> None:
        self.assertTrue(ANDROID_ADD_INT_DEF_PYTHON_PATH.exists())

        completed = subprocess.run(
            [sys.executable, str(ANDROID_ADD_INT_DEF_PYTHON_PATH)],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertNotEqual(0, completed.returncode)
        self.assertIn("usage", completed.stderr.lower())


if __name__ == "__main__":
    unittest.main()
