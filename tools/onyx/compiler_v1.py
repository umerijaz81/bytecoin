#!/usr/bin/env python3
"""Deterministic, fail-closed frontend and canonical IR encoder for Onyx language v1.

This tool is not a consensus verifier. It emits non-registrable frontend artifacts until the
approved Halo2 lowering and verifying-key regeneration stages are implemented and audited.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import pathlib
import re
import shutil
import tempfile
import unicodedata


COMPILER_VERSION = "1.0.0-alpha.1"
LANGUAGE_EDITION = "onyx-v1"
IR_DOMAIN = b"ONXIR\x01"
IR_ID_DOMAIN = b"bytecoin.onyx.ir.v1"
SCHEMA_DOMAIN = b"bytecoin.onyx.schema.v1"
MAX_SOURCE_FILES = 64
MAX_SOURCE_BYTES = 1 << 20
MAX_TOKEN_COUNT = 200_000
MAX_LOOP_BOUND = 1024
MAX_INSTRUCTIONS = 1_000_000
U64_MAX = (1 << 64) - 1


class CompileError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compiler_digest() -> str:
    # Git may materialize text with CRLF on Windows. Compiler identity commits to canonical LF bytes.
    data = pathlib.Path(__file__).resolve().read_bytes().replace(b"\r\n", b"\n")
    return sha256(data)


def checked_add(left: int, right: int, label: str) -> int:
    result = left + right
    if result > U64_MAX:
        raise CompileError("E_RESOURCE_OVERFLOW", f"{label} exceeds u64")
    return result


def uleb(value: int) -> bytes:
    if value < 0 or value > U64_MAX:
        raise CompileError("E_IR_INTEGER", "IR integer is outside u64")
    result = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        result.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(result)


def enc_bytes(value: bytes) -> bytes:
    return uleb(len(value)) + value


def enc_text(value: str) -> bytes:
    if unicodedata.normalize("NFC", value) != value:
        raise CompileError("E_IR_TEXT", "IR text is not Unicode NFC")
    return enc_bytes(value.encode("utf-8"))


def read_canonical_json(path: pathlib.Path, maximum: int = 1 << 20) -> tuple[object, bytes]:
    if path.is_symlink() or not path.is_file():
        raise CompileError("E_PACKAGE_FILE", f"required regular file is missing: {path.name}")
    data = path.read_bytes()
    if len(data) > maximum:
        raise CompileError("E_PACKAGE_SIZE", f"{path.name} exceeds its size limit")
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CompileError("E_PACKAGE_JSON", f"invalid {path.name}: {error}") from error
    if canonical_json(value) != data:
        raise CompileError("E_PACKAGE_CANONICAL", f"{path.name} is not canonical JSON")
    return value, data


def validate_path(text: object) -> str:
    if not isinstance(text, str) or not text or "\\" in text or text.startswith("/"):
        raise CompileError("E_PACKAGE_PATH", "source path must be nonempty, relative and use '/'")
    if unicodedata.normalize("NFC", text) != text:
        raise CompileError("E_PACKAGE_PATH", f"source path is not Unicode NFC: {text!r}")
    parts = text.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise CompileError("E_PACKAGE_PATH", f"source path has a forbidden segment: {text!r}")
    return text


@dataclasses.dataclass(frozen=True)
class SourcePackage:
    root: pathlib.Path
    manifest: dict
    manifest_bytes: bytes
    lock_bytes: bytes
    sources: tuple[tuple[str, bytes], ...]


REQUIRED_LIMITS = (
    "max_rows",
    "max_advice_columns",
    "max_fixed_columns",
    "max_instance_columns",
    "max_proof_bytes",
    "max_loop_iterations",
)


def load_package(root: pathlib.Path) -> SourcePackage:
    root = root.resolve()
    if not root.is_dir():
        raise CompileError("E_PACKAGE_ROOT", "package root is not a directory")
    manifest_value, manifest_bytes = read_canonical_json(root / "onyx-package.json")
    lock_value, lock_bytes = read_canonical_json(root / "onyx.lock")
    if not isinstance(manifest_value, dict) or set(manifest_value) != {
        "format",
        "name",
        "version",
        "language_edition",
        "compiler_version",
        "compiler_build_digest",
        "target_profile",
        "target_profile_digest",
        "sources",
        "exports",
        "limits",
        "dependency_lock_digest",
    }:
        raise CompileError("E_MANIFEST_FIELDS", "manifest fields differ from the v1 closed schema")
    manifest = manifest_value
    if manifest["format"] != 1 or manifest["language_edition"] != LANGUAGE_EDITION:
        raise CompileError("E_MANIFEST_VERSION", "unsupported package format or language edition")
    if manifest["compiler_version"] != COMPILER_VERSION or manifest["compiler_build_digest"] != compiler_digest():
        raise CompileError("E_COMPILER_PIN", "package does not pin this exact compiler build")
    for field in ("name", "version", "target_profile"):
        if not isinstance(manifest[field], str) or not manifest[field] or len(manifest[field]) > 128:
            raise CompileError("E_MANIFEST_VALUE", f"invalid manifest {field}")
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", manifest["name"]):
        raise CompileError("E_PACKAGE_NAME", "package name is not canonical")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?", manifest["version"]):
        raise CompileError("E_PACKAGE_VERSION", "package version is not semantic")
    if manifest["dependency_lock_digest"] != sha256(lock_bytes):
        raise CompileError("E_LOCK_DIGEST", "dependency lock digest mismatch")
    if not isinstance(lock_value, dict) or set(lock_value) != {"format", "dependencies"} or lock_value["format"] != 1:
        raise CompileError("E_LOCK_FIELDS", "dependency lock fields differ from the v1 closed schema")
    dependencies = lock_value["dependencies"]
    if not isinstance(dependencies, list):
        raise CompileError("E_LOCK_DEPENDENCIES", "dependencies must be an ordered list")
    previous_dep = ""
    for dependency in dependencies:
        if not isinstance(dependency, dict) or set(dependency) != {"name", "version", "artifact_sha256"}:
            raise CompileError("E_LOCK_DEPENDENCY", "dependency entry has unknown or missing fields")
        key = f"{dependency['name']}@{dependency['version']}"
        if key <= previous_dep or not re.fullmatch(r"[0-9a-f]{64}", str(dependency["artifact_sha256"])):
            raise CompileError("E_LOCK_ORDER", "dependencies are not unique, sorted and digest-pinned")
        previous_dep = key
    if dependencies:
        raise CompileError("E_DEPENDENCIES_UNSUPPORTED",
            "v1 alpha does not yet import dependencies; nonempty locks fail closed")
    limits = manifest["limits"]
    if not isinstance(limits, dict) or tuple(sorted(limits)) != tuple(sorted(REQUIRED_LIMITS)):
        raise CompileError("E_LIMIT_FIELDS", "resource limits differ from the v1 closed schema")
    for name in REQUIRED_LIMITS:
        if not isinstance(limits[name], int) or isinstance(limits[name], bool) or not 0 < limits[name] <= U64_MAX:
            raise CompileError("E_LIMIT_VALUE", f"invalid {name}")
    if limits["max_loop_iterations"] > MAX_LOOP_BOUND:
        raise CompileError("E_LOOP_PROFILE", "package loop bound exceeds the compiler profile")
    entries = manifest["sources"]
    if not isinstance(entries, list) or not 0 < len(entries) <= MAX_SOURCE_FILES:
        raise CompileError("E_SOURCE_COUNT", "source count is outside profile bounds")
    sources = []
    seen_casefold = set()
    previous = b""
    total = 0
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            raise CompileError("E_SOURCE_ENTRY", "source entry has unknown or missing fields")
        relative = validate_path(entry["path"])
        encoded = relative.encode("utf-8")
        if previous and encoded <= previous:
            raise CompileError("E_SOURCE_ORDER", "sources are not unique and UTF-8 byte sorted")
        previous = encoded
        folded = relative.casefold()
        if folded in seen_casefold:
            raise CompileError("E_SOURCE_CASE", "source paths collide on case-insensitive hosts")
        seen_casefold.add(folded)
        path = root.joinpath(*relative.split("/"))
        if path.is_symlink() or not path.is_file() or root not in path.resolve().parents:
            raise CompileError("E_SOURCE_FILE", f"source is missing, escaping or not regular: {relative}")
        data = path.read_bytes()
        total = checked_add(total, len(data), "source bytes")
        if total > MAX_SOURCE_BYTES or sha256(data) != entry["sha256"]:
            raise CompileError("E_SOURCE_DIGEST", f"source size/digest check failed: {relative}")
        if data.startswith(b"\xef\xbb\xbf") or b"\x00" in data or b"\r" in data:
            raise CompileError("E_SOURCE_TEXT", f"source contains BOM, NUL or non-LF newline: {relative}")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as error:
            raise CompileError("E_SOURCE_UTF8", f"source is not strict UTF-8: {relative}") from error
        if unicodedata.normalize("NFC", text) != text:
            raise CompileError("E_SOURCE_NFC", f"source is not Unicode NFC: {relative}")
        sources.append((relative, data))
    exports = manifest["exports"]
    if not isinstance(exports, list) or not exports or exports != sorted(set(exports)):
        raise CompileError("E_EXPORT_ORDER", "exports must be a nonempty sorted unique string list")
    if manifest["target_profile_digest"] != sha256(canonical_json(target_profile())):
        raise CompileError("E_TARGET_PROFILE_PIN", "package target-profile digest mismatch")
    declared_files = {"onyx-package.json", "onyx.lock", *(relative for relative, _ in sources)}
    actual_files = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise CompileError("E_PACKAGE_SYMLINK", "package contains a symlink")
        if path.is_file():
            actual_files.add(path.relative_to(root).as_posix())
    if actual_files != declared_files:
        raise CompileError("E_PACKAGE_UNDECLARED", "package contains undeclared or misses declared files")
    return SourcePackage(root, manifest, manifest_bytes, lock_bytes, tuple(sources))


TOKEN = re.compile(
    r"(?P<space>[ \t\n]+)|(?P<comment>//[^\n]*)|(?P<number>0|[1-9][0-9]*)|"
    r"(?P<ident>[A-Za-z_][A-Za-z0-9_]*)|(?P<op>->|\.\.|==|!=|<=|>=|&&|\|\||<<|>>|[{}()\[\],;:+\-*/%<>=!])"
)


@dataclasses.dataclass(frozen=True)
class Token:
    value: str
    offset: int


def lex(data: bytes, path: str) -> list[Token]:
    text = data.decode("utf-8")
    tokens = []
    offset = 0
    while offset != len(text):
        match = TOKEN.match(text, offset)
        if not match:
            raise CompileError("E_LEX", f"{path}:{offset}: unsupported character")
        if match.lastgroup not in ("space", "comment"):
            tokens.append(Token(match.group(), offset))
            if len(tokens) > MAX_TOKEN_COUNT:
                raise CompileError("E_TOKEN_LIMIT", f"{path}: token limit exceeded")
        offset = match.end()
    tokens.append(Token("<eof>", len(text)))
    return tokens


@dataclasses.dataclass(frozen=True)
class Type:
    name: str
    element: "Type | None" = None
    length: int = 0

    def canonical(self) -> str:
        if self.element is not None:
            return f"[{self.element.canonical()};{self.length}]"
        if self.name == "bytes":
            return f"bytes<{self.length}>"
        return self.name


@dataclasses.dataclass(frozen=True)
class Expr:
    kind: str
    value: object
    args: tuple["Expr", ...] = ()


@dataclasses.dataclass(frozen=True)
class Statement:
    kind: str
    value: object = None
    expression: Expr | None = None
    body: tuple["Statement", ...] = ()
    alternate: tuple["Statement", ...] = ()


@dataclasses.dataclass(frozen=True)
class Parameter:
    visibility: str
    name: str
    type: Type


@dataclasses.dataclass(frozen=True)
class Function:
    exported: bool
    name: str
    parameters: tuple[Parameter, ...]
    return_type: Type
    body: tuple[Statement, ...]


class Parser:
    def __init__(self, tokens: list[Token], path: str):
        self.tokens = tokens
        self.index = 0
        self.path = path

    def peek(self, value: str | None = None) -> bool | str:
        current = self.tokens[self.index].value
        return current == value if value is not None else current

    def take(self, value: str | None = None) -> str:
        token = self.tokens[self.index]
        if value is not None and token.value != value:
            raise CompileError("E_PARSE", f"{self.path}:{token.offset}: expected {value!r}, got {token.value!r}")
        self.index += 1
        return token.value

    def identifier(self) -> str:
        value = self.take()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value) or value in {
            "fn", "export", "public", "private", "let", "assert", "return", "if", "else", "for", "in"
        }:
            raise CompileError("E_IDENTIFIER", f"invalid identifier {value!r}")
        return value

    def parse_type(self) -> Type:
        if self.peek("["):
            self.take("[")
            element = self.parse_type()
            self.take(";")
            length = int(self.take())
            self.take("]")
            if not 0 < length <= MAX_LOOP_BOUND:
                raise CompileError("E_TYPE_BOUND", "array length is outside profile bounds")
            return Type("array", element, length)
        name = self.take()
        if name == "bytes":
            self.take("<")
            length = int(self.take())
            self.take(">")
            if not 0 < length <= 4096:
                raise CompileError("E_TYPE_BOUND", "byte-string length is outside profile bounds")
            return Type("bytes", None, length)
        if name not in ("bool", "u8", "u16", "u32", "u64", "field"):
            raise CompileError("E_TYPE", f"unsupported type {name!r}")
        return Type(name)

    def parse(self) -> list[Function]:
        functions = []
        while not self.peek("<eof>"):
            exported = False
            if self.peek("export"):
                self.take()
                exported = True
            self.take("fn")
            name = self.identifier()
            self.take("(")
            parameters = []
            if not self.peek(")"):
                while True:
                    visibility = self.take()
                    if visibility not in ("public", "private"):
                        raise CompileError("E_VISIBILITY", "parameter visibility must be explicit")
                    parameter_name = self.identifier()
                    self.take(":")
                    parameters.append(Parameter(visibility, parameter_name, self.parse_type()))
                    if not self.peek(","):
                        break
                    self.take()
            self.take(")")
            self.take("->")
            return_type = self.parse_type()
            body = self.parse_block()
            functions.append(Function(exported, name, tuple(parameters), return_type, body))
        return functions

    def parse_block(self) -> tuple[Statement, ...]:
        self.take("{")
        statements = []
        while not self.peek("}"):
            if self.peek("<eof>"):
                raise CompileError("E_PARSE", "unterminated block")
            statements.append(self.parse_statement())
        self.take("}")
        return tuple(statements)

    def parse_statement(self) -> Statement:
        if self.peek("let"):
            self.take()
            name = self.identifier()
            self.take(":")
            declared = self.parse_type()
            self.take("=")
            expression = self.expression()
            self.take(";")
            return Statement("let", (name, declared), expression)
        if self.peek("assert"):
            self.take()
            self.take("(")
            expression = self.expression()
            self.take(")")
            self.take(";")
            return Statement("assert", expression=expression)
        if self.peek("return"):
            self.take()
            expression = self.expression()
            self.take(";")
            return Statement("return", expression=expression)
        if self.peek("if"):
            self.take()
            condition = self.expression()
            body = self.parse_block()
            alternate = ()
            if self.peek("else"):
                self.take()
                alternate = self.parse_block()
            return Statement("if", expression=condition, body=body, alternate=alternate)
        if self.peek("for"):
            self.take()
            name = self.identifier()
            self.take("in")
            self.take("0")
            self.take("..")
            bound_text = self.take()
            if not bound_text.isdigit():
                raise CompileError("E_LOOP_BOUND", "loop bound must be a decimal constant")
            bound = int(bound_text)
            if bound > MAX_LOOP_BOUND:
                raise CompileError("E_LOOP_BOUND", "loop bound exceeds the compiler profile")
            return Statement("for", (name, bound), body=self.parse_block())
        token = self.tokens[self.index]
        raise CompileError("E_STATEMENT", f"{self.path}:{token.offset}: unsupported statement")

    def expression(self, minimum: int = 0) -> Expr:
        token = self.take()
        if token.isdigit():
            left = Expr("number", int(token))
        elif token in ("true", "false"):
            left = Expr("bool", token == "true")
        elif token == "!":
            left = Expr("unary", token, (self.expression(11),))
        elif token == "(":
            left = self.expression()
            self.take(")")
        elif re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token):
            if self.peek("("):
                self.take()
                arguments = []
                if not self.peek(")"):
                    while True:
                        arguments.append(self.expression())
                        if not self.peek(","):
                            break
                        self.take()
                self.take(")")
                left = Expr("call", token, tuple(arguments))
            else:
                left = Expr("name", token)
        else:
            raise CompileError("E_EXPRESSION", f"unexpected expression token {token!r}")
        precedence = {"||": 1, "&&": 2, "==": 3, "!=": 3, "<": 4, "<=": 4, ">": 4, ">=": 4,
                      "<<": 5, ">>": 5, "+": 6, "-": 6, "*": 7, "/": 7, "%": 7}
        while self.peek() in precedence and precedence[str(self.peek())] >= minimum:
            operator = self.take()
            right = self.expression(precedence[operator] + 1)
            left = Expr("binary", operator, (left, right))
        return left


@dataclasses.dataclass(frozen=True)
class Instruction:
    opcode: str
    result: int | None
    type: str
    operands: tuple[int, ...] = ()
    guard: int | None = None
    immediate: int | None = None
    text: str = ""


@dataclasses.dataclass(frozen=True)
class CompiledFunction:
    source: Function
    instructions: tuple[Instruction, ...]
    return_value: int


INTEGER_BITS = {"u8": 8, "u16": 16, "u32": 32, "u64": 64}
INTRINSICS = {
    "poseidon_hash": (("field", "field"), "field", 64),
    "merkle_root": (("field", "field"), "field", 96),
    "nullifier": (("field", "field"), "field", 80),
}


class Lowerer:
    def __init__(self, function_names: dict[str, Function], limits: dict, current_function: str):
        self.function_names = function_names
        self.limits = limits
        self.current_function = current_function
        self.instructions: list[Instruction] = []
        self.environment: dict[str, tuple[Type, int]] = {}
        self.return_value: int | None = None
        self.loop_iterations = 0
        self.active_guard: int | None = None

    def emit(self, opcode: str, type_: Type, operands=(), immediate=None, text="") -> int:
        result = len(self.instructions)
        self.instructions.append(Instruction(opcode, result, type_.canonical(), tuple(operands),
            self.active_guard, immediate, text))
        if len(self.instructions) > min(MAX_INSTRUCTIONS, self.limits["max_rows"]):
            raise CompileError("E_INSTRUCTION_LIMIT", "expanded instruction count exceeds package/profile limits")
        return result

    def expression(self, expression: Expr, expected: Type | None = None) -> tuple[Type, int]:
        if expression.kind == "number":
            if expected is None or expected.name not in INTEGER_BITS:
                raise CompileError("E_LITERAL_TYPE", "integer literal requires an unsigned integer context")
            if expression.value >= 1 << INTEGER_BITS[expected.name]:
                raise CompileError("E_LITERAL_RANGE", "integer literal is outside its contextual type")
            return expected, self.emit("const", expected, immediate=int(expression.value))
        if expression.kind == "bool":
            type_ = Type("bool")
            return type_, self.emit("const", type_, immediate=1 if expression.value else 0)
        if expression.kind == "name":
            if expression.value not in self.environment:
                raise CompileError("E_UNKNOWN_NAME", f"unknown value {expression.value!r}")
            return self.environment[str(expression.value)]
        if expression.kind == "unary":
            type_, operand = self.expression(expression.args[0], Type("bool"))
            if type_.name != "bool":
                raise CompileError("E_UNARY_TYPE", "logical not requires bool")
            return type_, self.emit("not", type_, (operand,))
        if expression.kind == "binary":
            operator = str(expression.value)
            left_type, left = self.expression(expression.args[0], expected)
            right_type, right = self.expression(expression.args[1], left_type)
            if left_type != right_type:
                raise CompileError("E_BINARY_TYPE", "binary operands have different types")
            if operator in ("&&", "||"):
                if left_type.name != "bool":
                    raise CompileError("E_BINARY_TYPE", "logical operands must be bool")
                return left_type, self.emit("and" if operator == "&&" else "or", left_type, (left, right))
            if operator in ("==", "!=", "<", "<=", ">", ">="):
                if left_type.name not in INTEGER_BITS and left_type.name not in ("bool", "field"):
                    raise CompileError("E_COMPARE_TYPE", "type is not comparable")
                if left_type.name == "field" and operator not in ("==", "!="):
                    raise CompileError("E_FIELD_ORDER", "field values have no ordering")
                return Type("bool"), self.emit({"==":"eq","!=":"ne","<":"lt","<=":"le",">":"gt",">=":"ge"}[operator], Type("bool"), (left, right))
            if left_type.name not in INTEGER_BITS and left_type.name != "field":
                raise CompileError("E_ARITHMETIC_TYPE", "arithmetic requires integers or field")
            if left_type.name == "field" and operator not in ("+", "-", "*", "/"):
                raise CompileError("E_FIELD_OPERATOR", "unsupported field operator")
            return left_type, self.emit({"+":"add","-":"sub","*":"mul","/":"div","%":"rem","<<":"shl",">>":"shr"}[operator], left_type, (left, right))
        if expression.kind == "call":
            name = str(expression.value)
            if name in INTRINSICS:
                parameters, result_type_name, _ = INTRINSICS[name]
                if len(parameters) != len(expression.args):
                    raise CompileError("E_CALL_ARITY", f"wrong intrinsic arity for {name}")
                operands = []
                for argument, parameter in zip(expression.args, parameters):
                    actual, value = self.expression(argument, Type(parameter))
                    if actual.name != parameter:
                        raise CompileError("E_CALL_TYPE", f"wrong intrinsic argument type for {name}")
                    operands.append(value)
                result_type = Type(result_type_name)
                return result_type, self.emit("intrinsic", result_type, operands, text=name)
            target = self.function_names.get(name)
            if target is None:
                raise CompileError("E_UNKNOWN_CALL", f"unknown function {name!r}")
            if name >= self.current_function:
                raise CompileError("E_CALL_ORDER", "direct calls must target an earlier name-sorted function")
            if len(target.parameters) != len(expression.args):
                raise CompileError("E_CALL_ARITY", f"wrong argument count for {name}")
            operands = []
            for argument, parameter in zip(expression.args, target.parameters):
                actual, value = self.expression(argument, parameter.type)
                if actual != parameter.type:
                    raise CompileError("E_CALL_TYPE", f"wrong argument type for {name}")
                operands.append(value)
            return target.return_type, self.emit("call", target.return_type, operands, text=name)
        raise CompileError("E_EXPRESSION_KIND", "unknown expression kind")

    def statements(self, statements: tuple[Statement, ...], guard: int | None = None, nested=False) -> None:
        previous_guard = self.active_guard
        self.active_guard = guard
        for statement in statements:
            if statement.kind == "let":
                name, declared = statement.value
                if name in self.environment:
                    raise CompileError("E_SSA_NAME", f"value {name!r} is declared more than once")
                actual, value = self.expression(statement.expression, declared)
                if actual != declared:
                    raise CompileError("E_LET_TYPE", f"initializer type differs for {name}")
                self.environment[name] = (declared, value)
            elif statement.kind == "assert":
                actual, value = self.expression(statement.expression, Type("bool"))
                if actual.name != "bool":
                    raise CompileError("E_ASSERT_TYPE", "assertion requires bool")
                self.instructions.append(Instruction("assert", None, "bool", (value,), guard))
            elif statement.kind == "return":
                if nested:
                    raise CompileError("E_NESTED_RETURN", "return inside if/for is not supported by v1 lowering")
                if self.return_value is not None:
                    raise CompileError("E_MULTIPLE_RETURN", "function has more than one return")
                actual, value = self.expression(statement.expression)
                self.return_value = value
                self.environment["$return_type"] = (actual, value)
            elif statement.kind == "if":
                actual, condition = self.expression(statement.expression, Type("bool"))
                if actual.name != "bool":
                    raise CompileError("E_IF_TYPE", "if condition requires bool")
                positive = condition if guard is None else self.emit("and", Type("bool"), (guard, condition))
                negative_condition = self.emit("not", Type("bool"), (condition,))
                negative = negative_condition if guard is None else self.emit("and", Type("bool"), (guard, negative_condition))
                before = dict(self.environment)
                self.statements(statement.body, positive, True)
                self.environment = dict(before)
                self.statements(statement.alternate, negative, True)
                self.environment = before
            elif statement.kind == "for":
                name, bound = statement.value
                self.loop_iterations = checked_add(self.loop_iterations, bound, "expanded loop iterations")
                if self.loop_iterations > self.limits["max_loop_iterations"]:
                    raise CompileError("E_LOOP_LIMIT", "expanded loops exceed package limit")
                before = dict(self.environment)
                for index in range(bound):
                    self.environment = dict(before)
                    value = self.emit("const", Type("u64"), immediate=index)
                    self.environment[name] = (Type("u64"), value)
                    self.statements(statement.body, guard, True)
                self.environment = before
            else:
                raise CompileError("E_STATEMENT_KIND", "unknown statement kind")
        self.active_guard = previous_guard

    def lower(self, function: Function) -> CompiledFunction:
        for parameter in function.parameters:
            if parameter.name in self.environment:
                raise CompileError("E_PARAMETER_DUPLICATE", f"duplicate parameter {parameter.name!r}")
            value = self.emit("parameter", parameter.type, text=parameter.visibility + ":" + parameter.name)
            self.environment[parameter.name] = (parameter.type, value)
        self.statements(function.body)
        if self.return_value is None:
            raise CompileError("E_MISSING_RETURN", f"function {function.name} has no return")
        actual = self.environment["$return_type"][0]
        if actual != function.return_type:
            raise CompileError("E_RETURN_TYPE", f"return type differs for {function.name}")
        self.instructions.append(Instruction("return", None, function.return_type.canonical(), (self.return_value,)))
        return CompiledFunction(function, tuple(self.instructions), self.return_value)


OPCODES = {name: index for index, name in enumerate((
    "parameter", "const", "not", "and", "or", "eq", "ne", "lt", "le", "gt", "ge",
    "add", "sub", "mul", "div", "rem", "shl", "shr", "intrinsic", "call", "assert", "return"
), 1)}


def target_profile() -> dict:
    return {
        "format": 1,
        "name": "halo2-ipa-pasta-onyx-compiler-v1",
        "language_edition": LANGUAGE_EDITION,
        "compiler_version": COMPILER_VERSION,
        "compiler_build_digest": compiler_digest(),
        "max_loop_bound": MAX_LOOP_BOUND,
        "instruction_set": list(OPCODES),
        "intrinsics": sorted(INTRINSICS),
        "backend_status": "frontend-only-not-registrable",
    }


def encode_ir(functions: list[CompiledFunction], profile_digest: bytes) -> bytes:
    result = bytearray(IR_DOMAIN)
    result.extend(profile_digest)
    result.extend(uleb(len(functions)))
    for function in functions:
        source = function.source
        result.extend(enc_text(source.name))
        result.append(1 if source.exported else 0)
        result.extend(uleb(len(source.parameters)))
        for parameter in source.parameters:
            result.append(1 if parameter.visibility == "public" else 2)
            result.extend(enc_text(parameter.name))
            result.extend(enc_text(parameter.type.canonical()))
        result.extend(enc_text(source.return_type.canonical()))
        result.extend(uleb(len(function.instructions)))
        for instruction in function.instructions:
            result.append(OPCODES[instruction.opcode])
            result.extend(uleb(0 if instruction.result is None else instruction.result + 1))
            result.extend(enc_text(instruction.type))
            result.extend(uleb(len(instruction.operands)))
            for operand in instruction.operands:
                result.extend(uleb(operand))
            result.extend(uleb(0 if instruction.guard is None else instruction.guard + 1))
            result.extend(uleb(0 if instruction.immediate is None else instruction.immediate + 1))
            result.extend(enc_text(instruction.text))
    return bytes(result)


def compile_sources(package: SourcePackage) -> tuple[list[CompiledFunction], bytes, dict, dict]:
    functions = []
    for path, data in package.sources:
        functions.extend(Parser(lex(data, path), path).parse())
    if not functions:
        raise CompileError("E_FUNCTION_COUNT", "package contains no functions")
    names = [function.name for function in functions]
    if names != sorted(names) or len(names) != len(set(names)):
        raise CompileError("E_FUNCTION_ORDER", "functions must be globally unique and name-sorted")
    mapping = {function.name: function for function in functions}
    actual_exports = [function.name for function in functions if function.exported]
    if actual_exports != package.manifest["exports"]:
        raise CompileError("E_EXPORT_MISMATCH", "manifest exports differ from source exports")
    compiled = [Lowerer(mapping, package.manifest["limits"], function.name).lower(function) for function in functions]
    profile = target_profile()
    if package.manifest["target_profile"] != profile["name"]:
        raise CompileError("E_TARGET_PROFILE_NAME", "package target-profile name mismatch")
    profile_bytes = canonical_json(profile)
    ir = encode_ir(compiled, hashlib.sha256(profile_bytes).digest())
    instruction_count = sum(len(function.instructions) for function in compiled)
    expanded_weights = {}
    constraint_weights = {}
    for function in compiled:
        expanded = 0
        constraints_for_function = 0
        for instruction in function.instructions:
            if instruction.opcode == "call":
                expanded = checked_add(expanded, expanded_weights[instruction.text], "expanded call instructions")
                constraints_for_function = checked_add(constraints_for_function,
                    constraint_weights[instruction.text], "expanded call constraints")
            else:
                expanded = checked_add(expanded, 1, "expanded instructions")
                cost = 1 + (INTRINSICS[instruction.text][2] if instruction.opcode == "intrinsic" else 0)
                constraints_for_function = checked_add(constraints_for_function, cost, "constraint estimate")
        expanded_weights[function.source.name] = expanded
        constraint_weights[function.source.name] = constraints_for_function
    expanded_instruction_count = sum(expanded_weights.values())
    constraints = sum(constraint_weights.values())
    rows = checked_add(constraints, len(compiled) * 8, "row estimate")
    public_inputs = sum(1 for function in functions for parameter in function.parameters if parameter.visibility == "public")
    private_inputs = sum(1 for function in functions for parameter in function.parameters if parameter.visibility == "private")
    limits = package.manifest["limits"]
    advice_columns = 3
    fixed_columns = 2
    instance_columns = 1 if public_inputs else 0
    witness_bytes = checked_add(private_inputs * 32, expanded_instruction_count * 32, "witness bytes")
    proving_memory = rows * (advice_columns + fixed_columns + instance_columns) * 32
    if proving_memory > U64_MAX:
        raise CompileError("E_RESOURCE_OVERFLOW", "proving memory exceeds u64")
    proof_bytes = checked_add(1024 + advice_columns * 64 + public_inputs * 32,
        (constraints + 7) // 8, "proof bytes")
    if (rows > limits["max_rows"] or advice_columns > limits["max_advice_columns"] or
            fixed_columns > limits["max_fixed_columns"] or instance_columns > limits["max_instance_columns"] or
            proof_bytes > limits["max_proof_bytes"]):
        raise CompileError("E_RESOURCE_LIMIT", "derived circuit resources exceed manifest limits")
    resources = {
        "format": 1,
        "functions": len(compiled),
        "ir_instructions": instruction_count,
        "expanded_instructions": expanded_instruction_count,
        "constraints_upper_bound": constraints,
        "rows_upper_bound": rows,
        "advice_columns_upper_bound": advice_columns,
        "fixed_columns_upper_bound": fixed_columns,
        "instance_columns_upper_bound": instance_columns,
        "public_inputs": public_inputs,
        "private_inputs": private_inputs,
        "witness_bytes_upper_bound": witness_bytes,
        "proving_memory_bytes_upper_bound": proving_memory,
        "lookups_upper_bound": 0,
        "verifier_work_upper_bound": checked_add(constraints, public_inputs * 2, "verifier work"),
        "proof_bytes_upper_bound": proof_bytes,
        "backend_measurements": None,
    }
    schemas = {}
    for function in functions:
        schema = {
            "format": 1,
            "function": function.name,
            "parameters": [{"name": parameter.name, "type": parameter.type.canonical(), "visibility": parameter.visibility} for parameter in function.parameters],
            "return_type": function.return_type.canonical(),
        }
        schema_bytes = canonical_json(schema)
        schema["schema_hash"] = sha256(SCHEMA_DOMAIN + schema_bytes)
        schemas[function.name] = schema
    return compiled, ir, {"profile": profile, "resources": resources}, schemas


def write_bundle(package: SourcePackage, destination: pathlib.Path) -> None:
    _, ir, metadata, schemas = compile_sources(package)
    parent = destination.resolve().parent
    parent.mkdir(parents=True, exist_ok=True)
    temporary = pathlib.Path(tempfile.mkdtemp(prefix=destination.name + ".tmp-", dir=parent))
    try:
        (temporary / "source").mkdir()
        (temporary / "schemas").mkdir()
        (temporary / "source" / "onyx-package.json").write_bytes(package.manifest_bytes)
        (temporary / "source" / "onyx.lock").write_bytes(package.lock_bytes)
        for relative, data in package.sources:
            output = temporary / "source" / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(data)
        (temporary / "program.onxir").write_bytes(ir)
        ir_id = sha256(IR_ID_DOMAIN + ir)
        (temporary / "ir-id.txt").write_bytes((ir_id + "\n").encode("ascii"))
        (temporary / "target-profile.json").write_bytes(canonical_json(metadata["profile"]))
        (temporary / "resources.json").write_bytes(canonical_json(metadata["resources"]))
        for name, schema in schemas.items():
            (temporary / "schemas" / f"{name}.json").write_bytes(canonical_json(schema))
        provenance = {
            "format": 1,
            "compiler_version": COMPILER_VERSION,
            "compiler_build_digest": compiler_digest(),
            "package_manifest_sha256": sha256(package.manifest_bytes),
            "dependency_lock_sha256": sha256(package.lock_bytes),
            "target_profile_sha256": sha256(canonical_json(metadata["profile"])),
            "ir_id": ir_id,
            "registrable": False,
            "missing_gate": "audited deterministic Halo2 lowering and verifying-key regeneration",
        }
        (temporary / "provenance.json").write_bytes(canonical_json(provenance))
        files = []
        for path in sorted((path for path in temporary.rglob("*") if path.is_file()), key=lambda item: item.relative_to(temporary).as_posix().encode("utf-8")):
            relative = path.relative_to(temporary).as_posix()
            files.append({"path": relative, "sha256": sha256(path.read_bytes()), "size": path.stat().st_size})
        (temporary / "SHA256MANIFEST.json").write_bytes(canonical_json({"format": 1, "files": files}))
        if destination.exists():
            raise CompileError("E_OUTPUT_EXISTS", "output directory already exists")
        os.replace(temporary, destination)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("package", nargs="?", type=pathlib.Path)
    parser.add_argument("output", nargs="?", type=pathlib.Path)
    parser.add_argument("--print-build-digest", action="store_true")
    parser.add_argument("--print-target-profile-digest", action="store_true")
    args = parser.parse_args()
    if args.print_build_digest:
        print(compiler_digest())
        return 0
    if args.print_target_profile_digest:
        print(sha256(canonical_json(target_profile())))
        return 0
    if args.package is None or args.output is None:
        parser.error("package and output are required")
    try:
        write_bundle(load_package(args.package), args.output)
    except CompileError as error:
        print(error)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
