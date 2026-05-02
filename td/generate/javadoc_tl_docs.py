#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs

from __future__ import annotations

import argparse
import html
import pathlib
import re

from tl_doc_core import TlDocumentationGenerator as SharedTlDocumentationGenerator


def _ucfirst(value: str) -> str:
    if not value:
        return ""
    return value[0].upper() + value[1:]


def _camelize_underscores(value: str) -> str:
    return re.sub(r"_([A-Za-z])", lambda match: match.group(1).upper(), value)


class JavadocTlDocumentationGenerator(SharedTlDocumentationGenerator):
    def __init__(self, nullable_type: str, nullable_annotation: str, java_version: int):
        super().__init__()
        self.nullable_type = nullable_type.strip()
        self.nullable_annotation = nullable_annotation.strip()
        self.java_version = int(java_version)

    def escape_documentation(self, doc: str) -> str:
        converted = re.sub(
            r'(?<!["A-Za-z_/])[A-Za-z]+(?:_[A-Za-z]+)+',
            lambda match: _camelize_underscores(match.group(0)),
            doc,
        )
        escaped = html.escape(converted, quote=True)
        return escaped.replace("*/", "*&#47;")

    def get_field_name(self, name: str, class_name: str) -> str:
        del class_name
        if name.startswith("param_"):
            name = name[6:]
        return _camelize_underscores(name.strip())

    def get_class_name(self, type_name: str) -> str:
        parts = type_name.strip("\r\n ;").split(".")
        return "".join(_ucfirst(part) for part in parts)

    def get_type_name(self, type_name: str) -> str:
        mapping = {
            "Bool": "boolean",
            "int32": "int",
            "int53": "long",
            "int64": "long",
            "double": "double",
            "string": "String",
            "bytes": "byte[]",
        }
        if type_name in mapping:
            return mapping[type_name]
        if type_name in {
            "bool",
            "int",
            "long",
            "Int",
            "Long",
            "Int32",
            "Int53",
            "Int64",
            "Double",
            "String",
            "Bytes",
        }:
            self.print_error(f"Wrong type {type_name}")
            return ""
        if type_name.startswith("vector"):
            if len(type_name) < 8 or type_name[6] != "<" or not type_name.endswith(">"):
                self.print_error(f"Wrong vector subtype in {type_name}")
                return ""
            return f"{self.get_type_name(type_name[7:-1])}[]"
        if re.search(r"[^A-Za-z0-9.]", type_name):
            self.print_error(f"Wrong type {type_name}")
            return ""
        return self.get_class_name(type_name)

    def get_base_class_name(self, is_function: bool) -> str:
        return "Function" if is_function else "Object"

    def need_remove_line(self, line: str) -> bool:
        stripped = line.strip()
        return (
            stripped.startswith("/**")
            or stripped.startswith("*")
            or (bool(self.nullable_type) and line.find(self.nullable_type) > 0)
        )

    def need_skip_line(self, line: str) -> bool:
        fixed_line = self.fix_line(line.strip())
        return (
            not fixed_line.startswith("public") and not self.is_header_line(fixed_line)
        ) or fixed_line == "public @interface Constructors {}"

    def is_header_line(self, line: str) -> bool:
        stripped = line.strip()
        return stripped == "@Override" or stripped == "@Constructors"

    def extract_class_name(self, line: str) -> str:
        marker = "public static class "
        marker_pos = line.find(marker)
        if marker_pos <= 0:
            return ""
        match = re.search(r"public static class (\w+)", line)
        if match is None:
            return ""
        return match.group(1)

    def fix_line(self, line: str) -> str:
        if "CONSTRUCTOR = " in line:
            return line[: line.index("=")]
        if self.nullable_annotation:
            return line.replace(f"{self.nullable_annotation} ", "")
        return line

    def add_global_documentation(self) -> None:
        nullable_type_import = ""
        if self.nullable_type:
            nullable_type_import = f"import {self.nullable_type};\n"

        self.add_documentation(
            "public class TdApi {",
            f"""{nullable_type_import}/**
 * This class contains as static nested classes all other TDLib interface
 * type-classes and function-classes.
 * <p>
 * It has no inner classes, functions or public members.
 */""",
        )

        self.add_documentation(
            "    public abstract static class Object {",
            """    /**
     * This class is a base class for all TDLib interface classes.
     */""",
        )

        self.add_documentation(
            "        public Object() {",
            """        /**
         * Default Object constructor.
         */""",
        )

        self.add_documentation(
            "        public abstract int getConstructor();",
            """        /**
         * Returns an identifier uniquely determining type of the object.
         *
         * @return a unique identifier of the object type.
         */""",
        )

        self.add_documentation(
            "        public native String toString();",
            """        /**
         * Returns a string representation of the object.
         *
         * @return a string representation of the object.
         */""",
        )

        self.add_documentation(
            "    public abstract static class Function<R extends Object> extends Object {",
            """    /**
     * This class is a base class for all TDLib interface function-classes.
     *
     * @param <R> The object type that is returned by the function
     */""",
        )

        self.add_documentation(
            "        public Function() {",
            """        /**
         * Default Function constructor.
         */""",
        )

        self.add_documentation(
            "        public static final int CONSTRUCTOR",
            """        /**
         * Identifier uniquely determining type of the object.
         */""",
        )

        self.add_documentation(
            "        public int getConstructor() {",
            """        /**
         * @return this.CONSTRUCTOR
         */""",
        )

    def add_abstract_class_documentation(self, class_name: str, value: str) -> None:
        self.add_documentation(
            f"    public abstract static class {class_name} extends Object {{",
            f"""    /**
     * This class is an abstract base class.
     * {value}
     */""",
        )
        self.add_documentation(
            f"        public {class_name}() {{",
            """        /**
         * Default class constructor.
         */""",
        )

    def get_function_return_type_description(
        self, return_type: str, for_constructor: bool
    ) -> str:
        shift = "         " if for_constructor else "     "
        return f"\n{shift}*\n{shift}* <p> Returns {{@link {return_type} {return_type}}} </p>"

    def add_class_documentation(
        self, class_name: str, base_class_name: str, return_type: str, description: str
    ) -> None:
        extends_part = (
            base_class_name if not return_type else f"{base_class_name}<{return_type}>"
        )
        self.add_documentation(
            f"    public static class {class_name} extends {extends_part} {{",
            f"""    /**
     * {description}
     */""",
        )

    def add_field_documentation(
        self,
        class_name: str,
        field_name: str,
        type_name: str,
        field_info: str,
        may_be_null: bool,
    ) -> None:
        full_line = f"{class_name}        public {type_name} {field_name};"
        self.add_documentation(
            full_line,
            f"""        /**
         * {field_info}
         */""",
        )
        if (
            may_be_null
            and self.nullable_annotation
            and (self.java_version >= 8 or not type_name.endswith("]"))
        ):
            self.add_line_replacement(
                full_line,
                f"        {self.nullable_annotation} public {type_name} {field_name};\n",
            )

    def add_default_constructor_documentation(
        self, class_name: str, class_description: str
    ) -> None:
        self.add_documentation(
            f"        public {class_name}() {{",
            f"""        /**
         * {class_description}
         */""",
        )

    def add_full_constructor_documentation(
        self,
        class_name: str,
        class_description: str,
        known_fields: dict[str, str],
        info: dict[str, str],
    ) -> None:
        params: list[str] = []
        for name, type_name in known_fields.items():
            params.append(
                f"{self.get_type_name(type_name)} {self.get_field_name(name, class_name)}"
            )
        full_constructor = f"        public {class_name}({', '.join(params)}) {{"

        doc_lines = [
            "        /**",
            f"         * {class_description}",
            "         *",
        ]
        for name in known_fields:
            doc_lines.append(
                f"         * @param {self.get_field_name(name, class_name)} {info[name]}"
            )
        doc_lines.append("         */")
        self.add_documentation(full_constructor, "\n".join(doc_lines))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Inject Javadoc comments into generated TdApi.java from td_api.tl"
    )
    parser.add_argument("tl_scheme_file", type=pathlib.Path)
    parser.add_argument("source_file", type=pathlib.Path)
    parser.add_argument("nullable_type", nargs="?", default="")
    parser.add_argument("nullable_annotation", nargs="?", default="")
    parser.add_argument("java_version", nargs="?", type=int, default=7)
    args = parser.parse_args()

    generator = JavadocTlDocumentationGenerator(
        args.nullable_type,
        args.nullable_annotation,
        args.java_version,
    )
    generator.generate(args.tl_scheme_file, args.source_file)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
