#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs

from __future__ import annotations

import argparse
import pathlib
import re

IMPORT_LINE = "import androidx.annotation.Nullable;"
IMPORT_REPLACEMENT = (
    "import androidx.annotation.IntDef;\n"
    "import androidx.annotation.Nullable;\n\n"
    "import java.lang.annotation.Retention;\n"
    "import java.lang.annotation.RetentionPolicy;"
)

CHILD_CLASS_PATTERN = re.compile(
    r"public static class ([A-Za-z0-9]+) extends ([A-Za-z0-9]+)"
)
ABSTRACT_CLASS_PATTERN = re.compile(
    r"public abstract static class ([A-Za-z0-9]+)(<R extends Object>)? extends Object [{]"
)


def apply_int_def_annotations(file_contents: str) -> str:
    if "androidx.annotation.IntDef" in file_contents:
        return file_contents

    if IMPORT_LINE not in file_contents:
        raise ValueError(
            "Expected androidx.annotation.Nullable import in TdApi.java before IntDef injection"
        )

    updated = file_contents.replace(IMPORT_LINE, IMPORT_REPLACEMENT, 1)

    children: dict[str, list[str]] = {}
    for child_name, parent_name in CHILD_CLASS_PATTERN.findall(updated):
        if parent_name == "Object":
            continue
        children.setdefault(parent_name, []).append(
            f"            {child_name}.CONSTRUCTOR"
        )

    def replace_abstract_class(match: re.Match[str]) -> str:
        class_name = match.group(1)
        values = ",\n".join(children.get(class_name, []))
        return (
            f"{match.group(0)}\n\n"
            "        /**\n"
            "         * Describes possible values returned by getConstructor().\n"
            "         */\n"
            "        @Retention(RetentionPolicy.SOURCE)\n"
            "        @IntDef({\n"
            f"{values}\n"
            "        })\n"
            "        public @interface Constructors {}\n\n"
            "        /**\n"
            "         * @return identifier uniquely determining type of the object.\n"
            "         */\n"
            "        @Constructors\n"
            "        @Override\n"
            "        public abstract int getConstructor();"
        )

    return ABSTRACT_CLASS_PATTERN.sub(replace_abstract_class, updated)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Inject Android @IntDef constructor annotations into generated TdApi.java"
    )
    parser.add_argument("java_file", type=pathlib.Path)
    args = parser.parse_args()

    original = args.java_file.read_text(encoding="utf-8")
    updated = apply_int_def_annotations(original)
    if updated != original:
        args.java_file.write_text(updated, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
