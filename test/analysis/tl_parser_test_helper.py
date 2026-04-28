# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT

from __future__ import annotations

import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest

THIS_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = THIS_DIR.parents[1]
TL_PARSER_DIR = REPO_ROOT / "td" / "generate" / "tl-parser"
TL_PARSER_SOURCE = TL_PARSER_DIR / "tl-parser.c"
TL_PARSER_MAIN = TL_PARSER_DIR / "tlc.c"
CRC32_SOURCE = TL_PARSER_DIR / "crc32.c"
TD_API_SCHEMA = REPO_ROOT / "td" / "generate" / "scheme" / "td_api.tl"

_TREE_ADD_CHILD_RE = re.compile(
    r"void\s+tree_add_child\s*\(struct tree \*P, struct tree \*C\)\s*\{(?P<body>.*?)^\}",
    flags=re.DOTALL | re.MULTILINE,
)


def read_tl_parser_source() -> str:
    return TL_PARSER_SOURCE.read_text(encoding="utf-8")


def tree_add_child_body() -> str:
    match = _TREE_ADD_CHILD_RE.search(read_tl_parser_source())
    if match is None:
        raise AssertionError(
            "tree_add_child definition must remain present in tl-parser.c"
        )
    return match.group("body")


def find_guard_offset(body: str) -> int:
    patterns = (
        r"if\s*\(\s*!t\s*\)",
        r"if\s*\(\s*t\s*==\s*0\s*\)",
        r"if\s*\(\s*t\s*==\s*NULL\s*\)",
    )
    for pattern in patterns:
        match = re.search(pattern, body)
        if match is not None:
            return match.start()
    return -1


class TlParserBinary:
    def __init__(self) -> None:
        compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
        if compiler is None:
            raise unittest.SkipTest(
                "A C compiler is required to run tl-parser integration tests"
            )
        self._compiler = compiler
        self._tempdir = tempfile.TemporaryDirectory()
        self._root = pathlib.Path(self._tempdir.name)
        self.binary_path = self._root / "tl-parser"
        self._build()

    def _build(self) -> None:
        subprocess.check_call(
            [
                self._compiler,
                "-std=gnu11",
                "-O0",
                "-g",
                str(TL_PARSER_MAIN),
                str(TL_PARSER_SOURCE),
                str(CRC32_SOURCE),
                "-I",
                str(TL_PARSER_DIR),
                "-lm",
                "-o",
                str(self.binary_path),
            ],
            cwd=REPO_ROOT,
        )

    def run_schema(
        self, schema_text: str, *extra_args: str, timeout_seconds: float = 5.0
    ) -> subprocess.CompletedProcess[str]:
        schema_path = self._root / "schema.tl"
        schema_path.write_text(schema_text, encoding="utf-8")
        return subprocess.run(
            [str(self.binary_path), *extra_args, str(schema_path)],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
        )

    def run_schema_file(
        self, schema_path: pathlib.Path, *extra_args: str, timeout_seconds: float = 5.0
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(self.binary_path), *extra_args, str(schema_path)],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
        )

    def cleanup(self) -> None:
        self._tempdir.cleanup()
