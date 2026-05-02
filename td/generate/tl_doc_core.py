# SPDX-FileCopyrightText: Copyright 2026 telemt community
# SPDX-License-Identifier: MIT
# telemt: https://github.com/telemt
# telemt: https://t.me/telemtrs

from __future__ import annotations

from dataclasses import dataclass
import pathlib
import re
import sys


@dataclass
class _SchemeParseState:
    description: str = ""
    description_line_count: int = 0
    current_class: str = ""
    is_function: bool = False
    need_class_description: bool = False


class TlDocumentationGenerator:
    def __init__(self) -> None:
        self.current_line = ""
        self.documentation: dict[str, str] = {}
        self.line_replacement: dict[str, str] = {}

    def is_built_in_type(self, type_name: str) -> bool:
        if type_name in {
            "Bool",
            "int32",
            "int53",
            "int64",
            "double",
            "string",
            "bytes",
        }:
            return True
        return (
            type_name.startswith("vector<")
            and type_name.endswith(">")
            and self.is_built_in_type(type_name[7:-1])
        )

    def print_error(self, error: str) -> None:
        print(f'{error} near line "{self.current_line.rstrip()}"', file=sys.stderr)

    def add_documentation(self, code: str, doc: str) -> None:
        if code in self.documentation:
            self.print_error(f'Duplicate documentation for "{code}"')
        self.documentation[code] = doc

    def add_line_replacement(self, line: str, new_line: str) -> None:
        if line in self.line_replacement:
            self.print_error(f'Duplicate line replacement for "{line}"')
        self.line_replacement[line] = new_line

    def add_dot(self, text: str) -> str:
        if not text:
            return ""
        if text.endswith("."):
            return text
        return f"{text}."

    def is_standalone_file(self) -> bool:
        return False

    def get_documentation_begin(self) -> str:
        return ""

    def get_documentation_end(self) -> str:
        return ""

    def escape_documentation(self, doc: str) -> str:
        raise NotImplementedError

    def get_field_name(self, name: str, class_name: str) -> str:
        raise NotImplementedError

    def get_class_name(self, name: str) -> str:
        raise NotImplementedError

    def get_type_name(self, type_name: str) -> str:
        raise NotImplementedError

    def get_base_class_name(self, is_function: bool) -> str:
        raise NotImplementedError

    def need_remove_line(self, line: str) -> bool:
        raise NotImplementedError

    def need_skip_line(self, line: str) -> bool:
        raise NotImplementedError

    def is_header_line(self, line: str) -> bool:
        raise NotImplementedError

    def extract_class_name(self, line: str) -> str:
        raise NotImplementedError

    def fix_line(self, line: str) -> str:
        raise NotImplementedError

    def add_global_documentation(self) -> None:
        raise NotImplementedError

    def add_abstract_class_documentation(self, class_name: str, value: str) -> None:
        raise NotImplementedError

    def get_function_return_type_description(
        self, return_type: str, for_constructor: bool
    ) -> str:
        raise NotImplementedError

    def add_class_documentation(
        self, class_name: str, base_class_name: str, return_type: str, description: str
    ) -> None:
        raise NotImplementedError

    def add_field_documentation(
        self,
        class_name: str,
        field_name: str,
        type_name: str,
        field_info: str,
        may_be_null: bool,
    ) -> None:
        raise NotImplementedError

    def add_default_constructor_documentation(
        self, class_name: str, class_description: str
    ) -> None:
        raise NotImplementedError

    def add_full_constructor_documentation(
        self,
        class_name: str,
        class_description: str,
        known_fields: dict[str, str],
        info: dict[str, str],
    ) -> None:
        raise NotImplementedError

    def _read_scheme_lines(self, tl_scheme_file: pathlib.Path) -> list[str]:
        return [
            line.strip()
            for line in tl_scheme_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def _handle_section_marker(self, line: str, state: _SchemeParseState) -> bool:
        if line == "---types---":
            state.is_function = False
            return True
        if line == "---functions---":
            state.is_function = True
            state.current_class = ""
            state.need_class_description = False
            return True
        return False

    def _handle_comment_line(self, line: str, state: _SchemeParseState) -> bool:
        if not line.startswith("/"):
            return False

        if not line.startswith("//"):
            self.print_error("Wrong comment")
            return True

        if len(line) > 2 and line[2] == "@":
            if not line.startswith("//@class "):
                state.description_line_count += 1
            state.description += line[2:].strip() + " "
            return True

        if len(line) > 2 and line[2] == "-":
            if "@" in line:
                state.description_line_count += 100
            state.description += line[3:].strip() + " "
            return True

        self.print_error("Unexpected comment")
        return True

    @staticmethod
    def _is_skipped_scheme_line(line: str) -> bool:
        return (
            "? =" in line
            or " = Vector t;" in line
            or line
            in {
                "boolFalse = Bool;",
                "boolTrue = Bool;",
                "bytes = Bytes;",
                "int32 = Int32;",
                "int53 = Int53;",
                "int64 = Int64;",
            }
        )

    def _split_doc_entry(self, doc: str) -> tuple[str, str] | None:
        if " " not in doc:
            self.print_error("Wrong documentation entry")
            return None
        key, value = doc.split(" ", 1)
        return key, value.strip()

    def _consume_pending_class_description(
        self, key: str, value: str, state: _SchemeParseState
    ) -> bool:
        if not state.need_class_description:
            return False

        if key == "description":
            state.need_class_description = False
            escaped = self.escape_documentation(self.add_dot(value))
            self.add_abstract_class_documentation(state.current_class, escaped)
            return True

        self.print_error("Expected abstract class description")
        return False

    def _handle_class_tag(self, key: str, value: str, state: _SchemeParseState) -> bool:
        if key != "class":
            return False

        state.current_class = self.get_class_name(value)
        state.need_class_description = True
        if state.is_function:
            self.print_error("Unexpected class definition")
        return True

    def _parse_doc_entries(
        self, description: str, state: _SchemeParseState
    ) -> dict[str, str] | None:
        if not description or not description.startswith("@"):
            self.print_error("Wrong description begin")
            return None

        if re.search(r"[^ ]@", description):
            self.print_error(f"Wrong documentation '@' usage: {description}")

        info: dict[str, str] = {}
        for doc in description.split("@")[1:]:
            parsed = self._split_doc_entry(doc)
            if parsed is None:
                continue
            key, value = parsed

            if self._consume_pending_class_description(key, value, state):
                continue
            if self._handle_class_tag(key, value, state):
                continue

            if key in info:
                self.print_error(f"Duplicate info about `{key}`")
            info[key] = value

        return info

    def _parse_definition_signature(
        self, line: str
    ) -> tuple[str, str, list[str]] | None:
        if line.count("=") != 1:
            self.print_error("Wrong '=' count")
            return None

        fields_part, type_part = line.split("=")
        fields = fields_part.strip().split(" ")
        if not fields:
            self.print_error("Wrong constructor name")
            return None

        class_name = self.get_class_name(fields[0])
        result_type = self.get_class_name(type_part)
        return class_name, result_type, fields[1:]

    def _validate_constructor_name(
        self, class_name: str, result_type: str, state: _SchemeParseState
    ) -> None:
        if state.is_function:
            return
        type_lower = result_type.lower()
        class_name_lower = class_name.lower()
        if (not state.current_class) == (type_lower != class_name_lower):
            self.print_error("Wrong constructor name")

    def _extract_known_fields(self, fields: list[str], info: dict[str, str]) -> dict[str, str]:
        known_fields: dict[str, str] = {}
        for field in fields:
            if ":" not in field:
                self.print_error(f"Wrong field declaration `{field}`")
                continue

            field_name, field_type = field.split(":", 1)
            param_name = f"param_{field_name}"
            if param_name in info:
                known_fields[param_name] = field_type
            elif field_name in info:
                known_fields[field_name] = field_type
            else:
                self.print_error(f"Have no documentation for field `{field_name}`")
        return known_fields

    def _validate_field_descriptions(self, info: dict[str, str], class_name: str) -> None:
        for name, value in info.items():
            if not value:
                self.print_error(
                    f"Documentation for field {name} of {class_name} is empty"
                )
            elif not value[0].isalnum() or not value[0].isascii():
                self.print_error(
                    f"Documentation for field {name} of {class_name} doesn't begin with a capital letter"
                )

    def _escape_info_entries(self, info: dict[str, str]) -> dict[str, str]:
        escaped: dict[str, str] = {}
        for key, value in info.items():
            escaped[key] = self.escape_documentation(self.add_dot(value))
        return escaped

    def _validate_info_alignment(
        self,
        info: dict[str, str],
        known_fields: dict[str, str],
        class_name: str,
        description_line_count: int,
    ) -> None:
        extra_info = set(info) - set(known_fields)
        for field_name in sorted(extra_info):
            self.print_error(f"Have info about nonexistent field `{field_name}`")

        if list(info.keys()) != list(known_fields.keys()):
            self.print_error(f"Have wrong documentation for class `{class_name}`")
            return

        if (description_line_count == 1 and len(known_fields) >= 4) or (
            description_line_count != len(known_fields) + 1
            and description_line_count != 1
        ):
            self.print_error(
                f"Documentation for fields of class `{class_name}` must be split to different lines"
            )

    def _emit_field_documentation(
        self,
        class_name: str,
        known_fields: dict[str, str],
        info: dict[str, str],
    ) -> None:
        for name, field_type in known_fields.items():
            field_info = info[name]
            may_be_null = "may be null" in field_info.lower()
            field_name = self.get_field_name(name, class_name)
            field_type_name = self.get_type_name(field_type)
            if self.is_built_in_type(field_type) and (
                may_be_null or "; pass null" in field_info.lower()
            ):
                self.print_error(
                    f"Field `{name}` of class `{class_name}` can't be marked as nullable"
                )
            self.add_field_documentation(
                class_name, field_name, field_type_name, field_info, may_be_null
            )

    def _emit_constructor_documentation(
        self,
        class_name: str,
        class_description: str,
        result_type: str,
        known_fields: dict[str, str],
        info: dict[str, str],
        is_function: bool,
    ) -> None:
        if is_function:
            default_constructor_prefix = "Default constructor for a function, which "
            full_constructor_prefix = "Creates a function, which "
            constructor_description = (
                class_description[:1].lower() + class_description[1:]
                if class_description
                else ""
            )
            constructor_description += self.get_function_return_type_description(
                self.get_type_name(result_type), True
            )
        else:
            default_constructor_prefix = ""
            full_constructor_prefix = ""
            constructor_description = class_description

        self.add_default_constructor_documentation(
            class_name, f"{default_constructor_prefix}{constructor_description}"
        )

        if known_fields:
            self.add_full_constructor_documentation(
                class_name,
                f"{full_constructor_prefix}{constructor_description}",
                known_fields,
                info,
            )

    def _process_schema_definition_line(
        self, line: str, state: _SchemeParseState
    ) -> None:
        description = state.description.strip()
        info = self._parse_doc_entries(description, state)
        if info is None:
            return

        signature = self._parse_definition_signature(line)
        if signature is None:
            state.description = ""
            state.description_line_count = 0
            return

        class_name, result_type, fields = signature
        if result_type != state.current_class:
            state.current_class = ""
            state.need_class_description = False

        self._validate_constructor_name(class_name, result_type, state)

        known_fields = self._extract_known_fields(fields, info)
        self._validate_field_descriptions(info, class_name)
        info = self._escape_info_entries(info)

        class_description = info.pop("description", "")
        if not class_description:
            self.print_error(f"Have no description for class `{class_name}`")

        self._validate_info_alignment(
            info, known_fields, class_name, state.description_line_count
        )

        base_class_name = state.current_class or self.get_base_class_name(state.is_function)
        return_type = ""
        effective_description = class_description
        if state.is_function:
            return_type = self.get_type_name(result_type)
            effective_description += self.get_function_return_type_description(
                return_type, False
            )
        self.add_class_documentation(
            class_name, base_class_name, return_type, effective_description
        )

        self._emit_field_documentation(class_name, known_fields, info)
        self._emit_constructor_documentation(
            class_name,
            class_description,
            result_type,
            known_fields,
            info,
            state.is_function,
        )

        state.description = ""
        state.description_line_count = 0

    def _write_standalone_output(self, source_file: pathlib.Path) -> None:
        result = self.get_documentation_begin() + "\n"
        for value in self.documentation.values():
            result += value + "\n"
        result += self.get_documentation_end()
        if not source_file.exists() or source_file.read_text(encoding="utf-8") != result:
            source_file.write_text(result, encoding="utf-8")

    def _find_documentation_for_line(self, fixed_line: str, current_class: str) -> str | None:
        return self.documentation.get(fixed_line) or self.documentation.get(
            current_class + fixed_line
        )

    def _find_line_replacement(self, fixed_line: str, current_class: str) -> str | None:
        return self.line_replacement.get(fixed_line) or self.line_replacement.get(
            current_class + fixed_line
        )

    def _process_inline_source_line(
        self,
        line: str,
        current_class: str,
        current_headers: str,
        result_parts: list[str],
    ) -> tuple[str, str]:
        self.current_line = line
        if self.need_remove_line(line):
            return current_class, current_headers

        if self.need_skip_line(line):
            result_parts.append(current_headers + line)
            return current_class, ""

        if self.is_header_line(line):
            return current_class, current_headers + line

        extracted_class = self.extract_class_name(line)
        if extracted_class:
            current_class = extracted_class

        fixed_line = self.fix_line(line).rstrip()
        doc = self._find_documentation_for_line(fixed_line, current_class)
        if not doc:
            self.print_error(f'Have no docs for "{fixed_line}"')
        else:
            result_parts.append(doc + "\n")

        replacement = self._find_line_replacement(fixed_line, current_class)
        if replacement is not None:
            line = replacement
        result_parts.append(current_headers + line)
        return current_class, ""

    def _write_inline_output(self, source_file: pathlib.Path) -> None:
        lines = source_file.read_text(encoding="utf-8").splitlines(keepends=True)
        result_parts: list[str] = []
        current_class = ""
        current_headers = ""

        for line in lines:
            current_class, current_headers = self._process_inline_source_line(
                line, current_class, current_headers, result_parts
            )

        result = "".join(result_parts)
        if source_file.read_text(encoding="utf-8") != result:
            source_file.write_text(result, encoding="utf-8")

    def generate(self, tl_scheme_file: pathlib.Path, source_file: pathlib.Path) -> None:
        lines = self._read_scheme_lines(tl_scheme_file)
        self.add_global_documentation()
        state = _SchemeParseState()

        for line in lines:
            self.current_line = line
            if self._handle_section_marker(line, state):
                continue
            if self._handle_comment_line(line, state):
                continue
            if self._is_skipped_scheme_line(line):
                continue
            self._process_schema_definition_line(line, state)

        if self.is_standalone_file():
            self._write_standalone_output(source_file)
            return

        self._write_inline_output(source_file)


