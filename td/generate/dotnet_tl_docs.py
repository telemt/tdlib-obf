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


class DotnetTlDocumentationGenerator(SharedTlDocumentationGenerator):
    def __init__(self, flavor_name: str):
        super().__init__()
        self.cpp_cli = flavor_name != "CX"

    def _get_array_type(self, type_name: str) -> str:
        if self.cpp_cli:
            return f"{type_name}[]"
        return f"System.Collections.Generic.IList{{{type_name}}}"

    def is_standalone_file(self) -> bool:
        return True

    def get_documentation_begin(self) -> str:
        documentation = """<?xml version="1.0"?>
<doc>
    <assembly>
        "Telegram.Td"
    </assembly>
    <members>
        <member name="M:Telegram.Td.Client.Create(Telegram.Td.ClientResultHandler)">
            <summary>
Creates new Client.
</summary>
            <param name="updateHandler">Handler for incoming updates.</param>
            <returns>Returns created Client.</returns>
        </member>
        <member name="M:Telegram.Td.Client.Run">
            <summary>
Launches a cycle which will fetch all results of queries to TDLib and incoming updates from TDLib.
Must be called once on a separate dedicated thread on which all updates and query results from all Clients will be handled.
Never returns.
</summary>
        </member>
        <member name="M:Telegram.Td.Client.Execute(Telegram.Td.Api.Function)">
            <summary>
Synchronously executes a TDLib request. Only a few marked accordingly requests can be executed synchronously.
</summary>
            <param name="function">Object representing a query to the TDLib.</param>
            <returns>Returns request result.</returns>
            <exception cref="T:System.NullReferenceException">Thrown when query is null.</exception>
        </member>
        <member name="M:Telegram.Td.Client.Send(Telegram.Td.Api.Function,Telegram.Td.ClientResultHandler)">
            <summary>
Sends a request to the TDLib.
</summary>
            <param name="function">Object representing a query to the TDLib.</param>
            <param name="handler">Result handler with OnResult method which will be called with result
of the query or with Telegram.Td.Api.Error as parameter. If it is null, nothing will be called.</param>
            <exception cref="T:System.NullReferenceException">Thrown when query is null.</exception>
        </member>
        <member name="T:Telegram.Td.Client">
            <summary>
Main class for interaction with the TDLib.
</summary>
        </member>
        <member name="M:Telegram.Td.ClientResultHandler.OnResult(Telegram.Td.Api.BaseObject)">
            <summary>
Callback called on result of query to TDLib or incoming update from TDLib.
</summary>
            <param name="object">Result of query or update of type Telegram.Td.Api.Update about new events.</param>
        </member>
        <member name="T:Telegram.Td.ClientResultHandler">
            <summary>
Interface for handler for results of queries to TDLib and incoming updates from TDLib.
</summary>
        </member>"""

        if self.cpp_cli:
            return documentation

        documentation += """
        <member name="M:Telegram.Td.Client.SetLogMessageCallback(System.Int32,Telegram.Td.LogMessageCallback)">
            <summary>
Sets the callback that will be called when a message is added to the internal TDLib log.
None of the TDLib methods can be called from the callback.
</summary>
            <param name="max_verbosity_level">The maximum verbosity level of messages for which the callback will be called.</param>
            <param name="callback">Callback that will be called when a message is added to the internal TDLib log.
Pass null to remove the callback.</param>
        </member>
        <member name="T:Telegram.Td.LogMessageCallback">
            <summary>
A type of callback function that will be called when a message is added to the internal TDLib log.
</summary>
            <param name="verbosityLevel">Log verbosity level with which the message was added from -1 up to 1024.
If 0, then TDLib will crash as soon as the callback returns.
None of the TDLib methods can be called from the callback.</param>
            <param name="message">The message added to the log.</param>
        </member>"""
        return documentation

    def get_documentation_end(self) -> str:
        return """    </members>
</doc>"""

    def escape_documentation(self, doc: str) -> str:
        converted = re.sub(
            r'(?<!["A-Za-z_/])[A-Za-z]+(?:_[A-Za-z]+)+',
            lambda match: _ucfirst(_camelize_underscores(match.group(0))),
            doc,
        )
        escaped = html.escape(converted, quote=True)
        return escaped.replace("*/", "*&#47;")

    def _get_parameter_name(self, name: str, class_name: str) -> str:
        del class_name
        if name.startswith("param_"):
            name = name[6:]
        return _camelize_underscores(name.strip())

    def get_field_name(self, name: str, class_name: str) -> str:
        field_name = _ucfirst(self._get_parameter_name(name, class_name))
        if field_name == class_name:
            field_name += "Value"
        return field_name

    def get_class_name(self, type_name: str) -> str:
        parts = type_name.strip("\r\n ;").split(".")
        return "".join(_ucfirst(part) for part in parts)

    def get_type_name(self, type_name: str) -> str:
        mapping = {
            "Bool": "System.Boolean",
            "int32": "System.Int32",
            "int53": "System.Int64",
            "int64": "System.Int64",
            "double": "System.Double",
            "string": "System.String",
            "bytes": self._get_array_type("System.Byte"),
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
            return self._get_array_type(self.get_type_name(type_name[7:-1]))
        if re.search(r"[^A-Za-z0-9.]", type_name):
            self.print_error(f"Wrong type {type_name}")
            return ""
        return self.get_class_name(type_name)

    def get_base_class_name(self, is_function: bool) -> str:
        return "Function" if is_function else "Object"

    def need_remove_line(self, line: str) -> bool:
        return line.strip().startswith("///")

    def need_skip_line(self, line: str) -> bool:
        stripped = line.strip()
        return (
            not stripped
            or stripped == "public:"
            or stripped == "private:"
            or stripped[0] == "}"
            or "Unmanaged" in stripped
            or "PrivateField" in stripped
            or "get()" in stripped
            or stripped.startswith("void set(")
            or bool(re.match(r"^[a-z]* class .*;", stripped))
            or stripped.startswith("namespace ")
            or stripped.startswith("#include ")
        )

    def is_header_line(self, line: str) -> bool:
        del line
        return False

    def extract_class_name(self, line: str) -> str:
        if "public ref class " in line or "public interface class " in line:
            parts = line.split(" ")
            if len(parts) > 3:
                return parts[3]
        return ""

    def fix_line(self, line: str) -> str:
        return line

    def add_global_documentation(self) -> None:
        self.add_documentation(
            "T:Object",
            """        <member name="T:Telegram.Td.Api.Object">
            <summary>
This class is a base class for all TDLib interface classes.
</summary>
        </member>""",
        )
        self.add_documentation(
            "T:Function",
            """        <member name="T:Telegram.Td.Api.Function">
            <summary>
This class is a base class for all TDLib interface function-classes.
</summary>
        </member>""",
        )

    def add_abstract_class_documentation(
        self, class_name: str, documentation: str
    ) -> None:
        self.add_documentation(
            f"T:{class_name}",
            f"""        <member name="T:Telegram.Td.Api.{class_name}">
            <summary>
This class is an abstract base class.
{documentation}
</summary>
        </member>""",
        )

    def get_function_return_type_description(
        self, return_type: str, for_constructor: bool
    ) -> str:
        del for_constructor
        return f'\r\n            <para>Returns <see cref="T:Telegram.Td.Api.{return_type}"/>.</para>'

    def add_class_documentation(
        self, class_name: str, base_class_name: str, return_type: str, description: str
    ) -> None:
        del base_class_name
        del return_type
        self.add_documentation(
            f"T:{class_name}",
            f"""        <member name="T:Telegram.Td.Api.{class_name}">
            <summary>
{description}
</summary>
        </member>""",
        )

    def add_field_documentation(
        self,
        class_name: str,
        field_name: str,
        type_name: str,
        field_info: str,
        may_be_null: bool,
    ) -> None:
        del type_name
        del may_be_null
        self.add_documentation(
            f"P:{class_name}.{field_name}",
            f"""        <member name="P:Telegram.Td.Api.{class_name}.{field_name}">
            <summary>
{field_info}
</summary>
        </member>""",
        )

    def add_default_constructor_documentation(
        self, class_name: str, class_description: str
    ) -> None:
        self.add_documentation(
            f"M:{class_name}.#ctor",
            f"""        <member name="M:Telegram.Td.Api.{class_name}.ToString">
            <summary>
Returns string representation of the object.
</summary>
            <returns>Returns string representation of the object.</returns>
        </member>
        <member name="M:Telegram.Td.Api.{class_name}.#ctor">
            <summary>
{class_description}
</summary>
        </member>""",
        )

    def add_full_constructor_documentation(
        self,
        class_name: str,
        class_description: str,
        known_fields: dict[str, str],
        info: dict[str, str],
    ) -> None:
        constructor_types: list[str] = []
        for type_name in known_fields.values():
            field_type = self.get_type_name(type_name)
            pos = 0
            while field_type.startswith("System.Collections.Generic.IList{", pos):
                pos += 33
            if not field_type[pos:].startswith("System."):
                field_type = field_type[:pos] + "Telegram.Td.Api." + field_type[pos:]
            constructor_types.append(field_type)
        full_constructor = ",".join(constructor_types)

        full_doc = f"""        <member name="M:Telegram.Td.Api.{class_name}.#ctor({full_constructor})">
            <summary>
{class_description}
</summary>"""
        for name in known_fields:
            full_doc += (
                f'\r\n            <param name="{self._get_parameter_name(name, class_name)}">'
                f"{info[name]}</param>"
            )
        full_doc += "\r\n        </member>"
        self.add_documentation(f"M:{class_name}.#ctor({full_constructor})", full_doc)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate .NET XML docs from td_api.tl using shared Python TL docs core"
    )
    parser.add_argument("tl_scheme_file", type=pathlib.Path)
    parser.add_argument("source_file", type=pathlib.Path)
    parser.add_argument("flavor_name", nargs="?", default="Windows")
    args = parser.parse_args()

    generator = DotnetTlDocumentationGenerator(args.flavor_name)
    generator.generate(args.tl_scheme_file, args.source_file)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
