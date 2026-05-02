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


class DoxygenTlDocumentationGenerator(SharedTlDocumentationGenerator):
    def get_parameter_type_name(self, type_name: str) -> str:
        mapping = {
            "Bool": "bool ",
            "int32": "int32 ",
            "int53": "int53 ",
            "int64": "int64 ",
            "double": "double ",
            "string": "string const &",
            "bytes": "bytes const &",
        }
        if type_name in mapping:
            return mapping[type_name]
        if type_name.startswith("vector"):
            if len(type_name) < 8 or type_name[6] != "<" or not type_name.endswith(">"):
                return ""
            return f"array<{self.get_type_name(type_name[7:-1])}> &&"
        if re.search(r"[^A-Za-z0-9.]", type_name):
            return ""
        return f"object_ptr<{self.get_class_name(type_name)}> &&"

    def escape_documentation(self, doc: str) -> str:
        escaped = html.escape(doc, quote=True)
        escaped = re.sub(
            r'&quot;((?:http|https|tg)://[^" ]*)&quot;',
            lambda match: f'&quot;<a href="{match.group(1)}">{match.group(1)}</a>&quot;',
            escaped,
        )
        escaped = escaped.replace("*/", "*&#47;")
        escaped = escaped.replace("#", r"\#")
        return escaped

    def get_field_name(self, name: str, class_name: str) -> str:
        if name.startswith("param_"):
            name = name[6:]
        return f"{name}_"

    def get_class_name(self, name: str) -> str:
        return "".join(name.strip("\r\n ;").split("."))

    def get_type_name(self, type_name: str) -> str:
        mapping = {
            "Bool": "bool",
            "int32": "int32",
            "int53": "int53",
            "int64": "int64",
            "double": "double",
            "string": "string",
            "bytes": "bytes",
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
            return f"array<{self.get_type_name(type_name[7:-1])}>"
        if re.search(r"[^A-Za-z0-9.]", type_name):
            self.print_error(f"Wrong type {type_name}")
            return ""
        return f"object_ptr<{self.get_class_name(type_name)}>"

    def get_base_class_name(self, is_function: bool) -> str:
        return "Function" if is_function else "Object"

    def need_remove_line(self, line: str) -> bool:
        stripped = line.strip()
        return (
            stripped.startswith("/**")
            or stripped.startswith("*")
            or stripped.startswith("///")
        )

    def need_skip_line(self, line: str) -> bool:
        stripped = line.strip()
        return (
            not stripped
            or stripped.startswith("}")
            or stripped == "public:"
            or line.startswith("#pragma ")
            or line.startswith("#include <")
            or stripped.startswith("return ")
            or stripped.startswith("namespace")
            or bool(re.match(r"class \w*;", stripped))
            or stripped == "if (value == nullptr) {"
            or stripped.startswith("result += ")
            or "result = " in stripped
            or stripped.startswith("result = ")
            or " : values" in stripped
            or "JNIEnv" in line
            or "jfieldID" in line
            or stripped == "virtual ~Object() {"
            or stripped
            == "virtual void store(TlStorerToString &s, const char *field_name) const = 0;"
            or stripped == "const char *&get_package_name_ref();"
            or stripped == "const char *get_git_commit_hash();"
        )

    def is_header_line(self, line: str) -> bool:
        return line.startswith("template <")

    def extract_class_name(self, line: str) -> str:
        if line.startswith("class "):
            return line.strip().split(" ")[1]
        return ""

    def fix_line(self, line: str) -> str:
        if (
            "ID = " in line
            or "ReturnType = " in line
            or line.startswith("using BaseObject = ")
        ):
            return line[: line.index("=")]
        if line.startswith("class Function: "):
            return "class Function"
        if line.startswith("class Object {") or line.startswith(
            "class Object: public TlObject {"
        ):
            return "class Object"
        return line

    def add_global_documentation(self) -> None:
        self.add_documentation(
            '#include "td/tl/TlObject.h"',
            """/**
 * \\file
 * Contains declarations of all functions and types which represent a public TDLib interface.
 */""",
        )
        self.add_documentation(
            "using int32 = std::int32_t;",
            """/**
 * This type is used to store 32-bit signed integers, which can be represented as Number in JSON.
 */""",
        )
        self.add_documentation(
            "using int53 = std::int64_t;",
            """/**
 * This type is used to store 53-bit signed integers, which can be represented as Number in JSON.
 */""",
        )
        self.add_documentation(
            "using int64 = std::int64_t;",
            """/**
 * This type is used to store 64-bit signed integers, which can't be represented as Number in JSON and are represented as String instead.
 */""",
        )
        self.add_documentation(
            "using string = std::string;",
            """/**
 * This type is used to store UTF-8 strings.
 */""",
        )
        self.add_documentation(
            "using bytes = std::string;",
            """/**
 * This type is used to store arbitrary sequences of bytes. In JSON interface the bytes are base64-encoded.
 */""",
        )
        self.add_documentation(
            "using array = std::vector<Type>;",
            """/**
 * This type is used to store a list of objects of any type and is represented as Array in JSON.
 */""",
        )
        self.add_documentation(
            "using BaseObject",
            """/**
 * This class is a base class for all TDLib API classes and functions.
 */""",
        )
        self.add_documentation(
            "using object_ptr = ::td::tl_object_ptr<Type>;",
            """/**
 * A smart wrapper to store a pointer to a TDLib API object. Can be treated as an analogue of std::unique_ptr.
 */""",
        )
        self.add_documentation(
            "object_ptr<Type> make_object(Args &&... args) {",
            """/**
 * A function to create a dynamically allocated TDLib API object. Can be treated as an analogue of std::make_unique.
 * Usage example:
 * \\code
 * auto get_me_request = td::td_api::make_object<td::td_api::getMe>();
 * auto message_text = td::td_api::make_object<td::td_api::formattedText>("Hello, world!!!",
 *                     td::td_api::array<td::td_api::object_ptr<td::td_api::textEntity>>());
 * auto send_message_request = td::td_api::make_object<td::td_api::sendMessage>(chat_id, nullptr, nullptr, nullptr, nullptr,
 *      td::td_api::make_object<td::td_api::inputMessageText>(std::move(message_text), nullptr, true));
 * \\endcode
 *
 * \\tparam Type Type of object to construct.
 * \\param[in] args Arguments to pass to the object constructor.
 * \\return Wrapped pointer to the created object.
 */""",
        )
        self.add_documentation(
            "object_ptr<ToType> move_object_as(FromType &&from) {",
            """/**
 * A function to cast a wrapped in td::td_api::object_ptr TDLib API object to its subclass or superclass.
 * Casting an object to an incorrect type will lead to undefined behaviour.
 * Usage example:
 * \\code
 * td::td_api::object_ptr<td::td_api::callState> call_state = ...;
 * switch (call_state->get_id()) {
 *   case td::td_api::callStatePending::ID: {
 *     auto state = td::td_api::move_object_as<td::td_api::callStatePending>(call_state);
 *     break;
 *   }
 *   case td::td_api::callStateExchangingKeys::ID: {
 *     break;
 *   }
 *   case td::td_api::callStateReady::ID: {
 *     auto state = td::td_api::move_object_as<td::td_api::callStateReady>(call_state);
 *     break;
 *   }
 *   case td::td_api::callStateHangingUp::ID: {
 *     break;
 *   }
 *   case td::td_api::callStateDiscarded::ID: {
 *     auto state = td::td_api::move_object_as<td::td_api::callStateDiscarded>(call_state);
 *     break;
 *   }
 *   case td::td_api::callStateError::ID: {
 *     auto state = td::td_api::move_object_as<td::td_api::callStateError>(call_state);
 *     break;
 *   }
 *   default:
 *     assert(false);
 * }
 * \\endcode
 *
 * \\tparam ToType Type of TDLib API object to move to.
 * \\tparam FromType Type of TDLib API object to move from, this is auto-deduced.
 * \\param[in] from Wrapped in td::td_api::object_ptr pointer to a TDLib API object.
 */""",
        )
        self.add_documentation(
            "std::string to_string(const BaseObject &value);",
            """/**
 * Returns a string representation of a TDLib API object.
 * \\param[in] value The object.
 * \\return Object string representation.
 */""",
        )
        self.add_documentation(
            "std::string to_string(const object_ptr<T> &value) {",
            """/**
 * Returns a string representation of a TDLib API object.
 * \\tparam T Object type, auto-deduced.
 * \\param[in] value The object.
 * \\return Object string representation.
 */""",
        )
        self.add_documentation(
            "std::string to_string(const std::vector<object_ptr<T>> &values) {",
            """/**
 * Returns a string representation of a list of TDLib API objects.
 * \\tparam T Object type, auto-deduced.
 * \\param[in] values The objects.
 * \\return Objects string representation.
 */""",
        )
        self.add_documentation(
            "  void store(TlStorerToString &s, const char *field_name) const final;",
            """  /**
   * Helper function for to_string method. Appends string representation of the object to the storer.
   * \\param[in] s Storer to which object string representation will be appended.
   * \\param[in] field_name Object field_name if applicable.
   */""",
        )
        self.add_documentation(
            "class Object",
            """/**
 * This class is a base class for all TDLib API classes.
 */""",
        )
        self.add_documentation(
            "class Function",
            """/**
 * This class is a base class for all TDLib API functions.
 */""",
        )
        self.add_documentation(
            "  static const std::int32_t ID",
            "  /// Identifier uniquely determining a type of the object.",
        )
        self.add_documentation(
            "  std::int32_t get_id() const final {",
            """  /**
   * Returns identifier uniquely determining a type of the object.
   * \\return this->ID.
   */""",
        )
        self.add_documentation(
            "  virtual std::int32_t get_id() const = 0;",
            """  /**
   * Returns identifier uniquely determining a type of the object.
   * \\return this->ID.
   */""",
        )
        self.add_documentation(
            "  using ReturnType",
            "  /// Typedef for the type returned by the function.",
        )

    def add_abstract_class_documentation(self, class_name: str, value: str) -> None:
        self.add_documentation(
            f"class {class_name}: public Object {{",
            f"""/**
 * This class is an abstract base class.
 * {value}
 */""",
        )

    def get_function_return_type_description(
        self, return_type: str, for_constructor: bool
    ) -> str:
        shift = "   " if for_constructor else " "
        return f"\n{shift}*\n{shift}* Returns {return_type}."

    def add_class_documentation(
        self, class_name: str, base_class_name: str, return_type: str, description: str
    ) -> None:
        self.add_documentation(
            f"class {class_name} final : public {base_class_name} {{",
            f"""/**
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
        self.add_documentation(
            class_name + f"  {type_name} {field_name};",
            f"  /// {field_info}",
        )

    def add_default_constructor_documentation(
        self, class_name: str, class_description: str
    ) -> None:
        self.add_documentation(
            f"  {class_name}();",
            f"""  /**
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
        explicit = "explicit " if len(known_fields) == 1 else ""
        params = ", ".join(
            self.get_parameter_type_name(type_name)
            + self.get_field_name(name, class_name)
            for name, type_name in known_fields.items()
        )
        signature = f"  {explicit}{class_name}({params});"
        lines = [
            "  /**",
            f"   * {class_description}",
            "   *",
        ]
        for name in known_fields:
            lines.append(
                f"   * \\param[in] {self.get_field_name(name, class_name)} {info[name]}"
            )
        lines.append("   */")
        self.add_documentation(signature, "\n".join(lines))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Inject Doxygen comments into generated td_api.h from td_api.tl"
    )
    parser.add_argument("tl_scheme_file", type=pathlib.Path)
    parser.add_argument("source_file", type=pathlib.Path)
    args = parser.parse_args()

    generator = DoxygenTlDocumentationGenerator()
    generator.generate(args.tl_scheme_file, args.source_file)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
