#!/usr/bin/env python3
"""Deterministic, fail-closed frontend and canonical IR encoder for Onyx language v1.

This tool is not a consensus verifier. It emits non-registrable frontend artifacts until the
approved Halo2 lowering and verifying-key regeneration stages are implemented and audited.
"""

from __future__ import annotations

import argparse
import dataclasses
import functools
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unicodedata


COMPILER_VERSION = "1.0.0-alpha.1"
LANGUAGE_EDITION = "onyx-v1"
IR_DOMAIN = b"ONXIR\x01"
IR_ID_DOMAIN = b"bytecoin.onyx.ir.v1"
SCHEMA_DOMAIN = b"bytecoin.onyx.schema.v1"
MAX_SOURCE_FILES = 64
MAX_SOURCE_BYTES = 1 << 20
MAX_DEPENDENCIES = 32
MAX_DEPENDENCY_BYTES = 4 << 20
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
class LibraryPackage:
    name: str
    version: str
    digest: str
    root: pathlib.Path
    manifest_bytes: bytes
    sources: tuple[tuple[str, bytes], ...]


@dataclasses.dataclass(frozen=True)
class SourcePackage:
    root: pathlib.Path
    manifest: dict
    manifest_bytes: bytes
    lock_bytes: bytes
    sources: tuple[tuple[str, bytes], ...]
    dependencies: tuple[LibraryPackage, ...]


REQUIRED_LIMITS = (
    "max_rows",
    "max_advice_columns",
    "max_fixed_columns",
    "max_instance_columns",
    "max_proof_bytes",
    "max_loop_iterations",
)


def tree_digest(files: tuple[tuple[str, bytes], ...]) -> str:
    digest = hashlib.sha256(b"bytecoin.onyx.dependency-tree.v1")
    for relative, data in files:
        digest.update(enc_text(relative))
        digest.update(enc_bytes(data))
    return digest.hexdigest()


def load_library(store: pathlib.Path, dependency: dict) -> LibraryPackage:
    digest = dependency["artifact_sha256"]
    root = (store / digest).resolve()
    if store.resolve() not in root.parents or not root.is_dir() or root.is_symlink():
        raise CompileError("E_DEPENDENCY_MISSING", f"content-addressed dependency is missing: {digest}")
    manifest_value, manifest_bytes = read_canonical_json(root / "onyx-library.json")
    if not isinstance(manifest_value, dict) or set(manifest_value) != {"format", "name", "version", "sources"}:
        raise CompileError("E_LIBRARY_FIELDS", "library manifest differs from the v1 closed schema")
    if manifest_value["format"] != 1 or manifest_value["name"] != dependency["name"] or \
            manifest_value["version"] != dependency["version"]:
        raise CompileError("E_LIBRARY_IDENTITY", "library identity differs from its lock entry")
    entries = manifest_value["sources"]
    if not isinstance(entries, list) or not 0 < len(entries) <= MAX_SOURCE_FILES:
        raise CompileError("E_LIBRARY_SOURCES", "library source count is outside bounds")
    sources = []
    previous = b""
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            raise CompileError("E_LIBRARY_SOURCE", "library source entry has unknown or missing fields")
        relative = validate_path(entry["path"])
        encoded = relative.encode("utf-8")
        if previous and encoded <= previous:
            raise CompileError("E_LIBRARY_ORDER", "library sources are not unique and byte-sorted")
        previous = encoded
        path = root.joinpath(*relative.split("/"))
        if path.is_symlink() or not path.is_file() or root not in path.resolve().parents:
            raise CompileError("E_LIBRARY_FILE", f"unsafe library source: {relative}")
        data = path.read_bytes()
        if len(data) > MAX_SOURCE_BYTES or sha256(data) != entry["sha256"] or b"\r" in data or b"\x00" in data:
            raise CompileError("E_LIBRARY_DIGEST", f"library source framing/digest failed: {relative}")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as error:
            raise CompileError("E_LIBRARY_UTF8", f"library source is not strict UTF-8: {relative}") from error
        if unicodedata.normalize("NFC", text) != text:
            raise CompileError("E_LIBRARY_NFC", f"library source is not Unicode NFC: {relative}")
        sources.append((relative, data))
    declared = {"onyx-library.json", *(relative for relative, _ in sources)}
    actual = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise CompileError("E_LIBRARY_SYMLINK", "library contains a symlink")
        if path.is_file():
            actual.add(path.relative_to(root).as_posix())
    if actual != declared:
        raise CompileError("E_LIBRARY_UNDECLARED", "library contains undeclared or misses declared files")
    digest_files = (("onyx-library.json", manifest_bytes), *sources)
    if tree_digest(tuple(digest_files)) != digest:
        raise CompileError("E_LIBRARY_TREE_DIGEST", "library tree digest differs from its store key")
    return LibraryPackage(dependency["name"], dependency["version"], digest, root,
                          manifest_bytes, tuple(sources))


def load_package(root: pathlib.Path, dependency_store: pathlib.Path | None = None) -> SourcePackage:
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
        "vectors",
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
    if not isinstance(dependencies, list) or len(dependencies) > MAX_DEPENDENCIES:
        raise CompileError("E_LOCK_DEPENDENCIES", "dependencies must be a bounded ordered list")
    previous_dep = ""
    for dependency in dependencies:
        if not isinstance(dependency, dict) or set(dependency) != {"name", "version", "artifact_sha256"}:
            raise CompileError("E_LOCK_DEPENDENCY", "dependency entry has unknown or missing fields")
        if not isinstance(dependency["name"], str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", dependency["name"]):
            raise CompileError("E_LOCK_DEPENDENCY", "dependency name is not canonical")
        if not isinstance(dependency["version"], str) or not re.fullmatch(
                r"[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?", dependency["version"]):
            raise CompileError("E_LOCK_DEPENDENCY", "dependency version is not semantic")
        key = f"{dependency['name']}@{dependency['version']}"
        if key <= previous_dep or not re.fullmatch(r"[0-9a-f]{64}", str(dependency["artifact_sha256"])):
            raise CompileError("E_LOCK_ORDER", "dependencies are not unique, sorted and digest-pinned")
        previous_dep = key
    loaded_dependencies = []
    if dependencies and dependency_store is None:
        raise CompileError("E_DEPENDENCY_STORE", "nonempty lock requires an explicit dependency store")
    if dependency_store is not None:
        dependency_store = dependency_store.resolve()
        if not dependency_store.is_dir() or dependency_store.is_symlink():
            raise CompileError("E_DEPENDENCY_STORE", "dependency store is not a regular directory")
    for dependency in dependencies:
        loaded_dependencies.append(load_library(dependency_store, dependency))
    dependency_bytes = sum(len(library.manifest_bytes) + sum(len(data) for _, data in library.sources)
                           for library in loaded_dependencies)
    if dependency_bytes > MAX_DEPENDENCY_BYTES:
        raise CompileError("E_DEPENDENCY_SIZE", "aggregate dependency bytes exceed the profile")
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
    vectors = manifest["vectors"]
    if not isinstance(vectors, list) or len(vectors) > 1024:
        raise CompileError("E_VECTOR_COUNT", "program vector count is outside bounds")
    for vector in vectors:
        if not isinstance(vector, dict) or set(vector) not in (
                {"function", "inputs", "expected"}, {"function", "inputs", "expect_failure"}):
            raise CompileError("E_VECTOR_FIELDS", "program vector has unknown or missing fields")
        if vector["function"] not in exports or not isinstance(vector["inputs"], list):
            raise CompileError("E_VECTOR_FUNCTION", "program vector targets an unknown export")
        if "expect_failure" in vector and vector["expect_failure"] is not True:
            raise CompileError("E_VECTOR_FAILURE", "negative vector must explicitly expect failure")
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
    return SourcePackage(root, manifest, manifest_bytes, lock_bytes, tuple(sources), tuple(loaded_dependencies))


TOKEN = re.compile(
    r"(?P<space>[ \t\n]+)|(?P<comment>//[^\n]*)|(?P<number>0|[1-9][0-9]*)|"
    r"(?P<hex>hex\"[0-9a-f]*\")|(?P<ident>[A-Za-z_][A-Za-z0-9_]*)|"
    r"(?P<op>->|\.\.|==|!=|<=|>=|&&|\|\||<<|>>|[.{}()\[\],;:+\-*/%<>=!])"
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
    fields: tuple[tuple[str, "Type"], ...] = ()

    def canonical(self) -> str:
        if self.element is not None:
            return f"[{self.element.canonical()};{self.length}]"
        if self.name == "bytes":
            return f"bytes<{self.length}>"
        if self.name == "record":
            return "{" + ",".join(name + ":" + type_.canonical() for name, type_ in self.fields) + "}"
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
    def __init__(self, tokens: list[Token], path: str, records: dict[str, Type]):
        self.tokens = tokens
        self.index = 0
        self.path = path
        self.records = records

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
            "fn", "record", "export", "public", "private", "let", "assert", "return", "if", "else", "for", "in"
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
            if name in self.records:
                return self.records[name]
            raise CompileError("E_TYPE", f"unsupported or forward-declared type {name!r}")
        return Type(name)

    def parse(self) -> list[Function]:
        functions = []
        while not self.peek("<eof>"):
            if self.peek("record"):
                self.take()
                name = self.identifier()
                if name in self.records:
                    raise CompileError("E_RECORD_DUPLICATE", f"duplicate record {name!r}")
                self.take("{")
                fields = []
                while not self.peek("}"):
                    field_name = self.identifier()
                    self.take(":")
                    fields.append((field_name, self.parse_type()))
                    self.take(";")
                self.take("}")
                if not fields or [field[0] for field in fields] != sorted(set(field[0] for field in fields)):
                    raise CompileError("E_RECORD_FIELDS", "record fields must be nonempty, unique and name-sorted")
                self.records[name] = Type("record", fields=tuple(fields))
                continue
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
        elif token.startswith('hex"'):
            payload = token[4:-1]
            if len(payload) % 2:
                raise CompileError("E_BYTES_LITERAL", "hex literal must contain whole bytes")
            left = Expr("bytes", bytes.fromhex(payload))
        elif token in ("true", "false"):
            left = Expr("bool", token == "true")
        elif token == "!":
            left = Expr("unary", token, (self.expression(11),))
        elif token == "(":
            left = self.expression()
            self.take(")")
        elif token == "[":
            elements = []
            if not self.peek("]"):
                while True:
                    elements.append(self.expression())
                    if not self.peek(","):
                        break
                    self.take()
            self.take("]")
            left = Expr("array", None, tuple(elements))
        elif re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token):
            if self.peek("{"):
                self.take()
                field_names = []
                field_values = []
                while not self.peek("}"):
                    field_names.append(self.identifier())
                    self.take(":")
                    field_values.append(self.expression())
                    if not self.peek(","):
                        break
                    self.take()
                self.take("}")
                left = Expr("record", (token, tuple(field_names)), tuple(field_values))
            elif self.peek("("):
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
        while self.peek("["):
            self.take()
            index = self.expression()
            self.take("]")
            left = Expr("index", None, (left, index))
        while self.peek("."):
            self.take()
            left = Expr("field", self.identifier(), (left,))
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
    "nullifier": (("field", "field", "field"), "field", 160),
}
EXPORT_ID_DOMAIN = b"bytecoin.onyx.compiler-export.v1"


class _PoseidonGrain:
    def __init__(self):
        self.state = [1] * 80
        def set_bits(offset: int, length: int, value: int) -> None:
            for index in range(length):
                self.state[offset + length - 1 - index] = (value >> index) & 1
        set_bits(0, 2, 1)       # prime-order field
        set_bits(2, 4, 0)       # x^alpha S-box
        set_bits(6, 12, 255)    # Pasta field bit length
        set_bits(18, 12, 3)     # width
        set_bits(30, 10, 8)     # full rounds
        set_bits(40, 10, 56)    # partial rounds
        self.next_bit = 80
        for _ in range(20):
            self._load_next_8_bits()
            self.next_bit = 80

    def _load_next_8_bits(self) -> None:
        value = 0
        for index in range(8):
            value |= (self.state[index + 62] ^ self.state[index + 51] ^
                      self.state[index + 38] ^ self.state[index + 23] ^
                      self.state[index + 13] ^ self.state[index]) << index
        self.state = self.state[8:] + self.state[:8]
        self.next_bit -= 8
        for index in range(8):
            self.state[self.next_bit + index] = (value >> index) & 1

    def _bit(self) -> int:
        if self.next_bit == 80:
            self._load_next_8_bits()
        result = self.state[self.next_bit]
        self.next_bit += 1
        return result

    def _self_shrinking_bit(self) -> int:
        while self._bit() == 0:
            self._bit()
        return self._bit()

    def _candidate(self) -> int:
        return sum(self._self_shrinking_bit() << (254 - index) for index in range(255))

    def field(self) -> int:
        while True:
            value = self._candidate()
            if value < PASTA_FP_MODULUS:
                return value

    def field_without_rejection(self) -> int:
        return self._candidate() % PASTA_FP_MODULUS


@functools.lru_cache(maxsize=1)
def _poseidon_constants():
    grain = _PoseidonGrain()
    rounds = tuple(tuple(grain.field() for _ in range(3)) for _ in range(64))
    while True:
        values = [grain.field_without_rejection() for _ in range(6)]
        if len(set(values)) == 6:
            break
    xs, ys = values[:3], values[3:]
    mds = tuple(tuple(pow((left + right) % PASTA_FP_MODULUS, -1, PASTA_FP_MODULUS)
                      for right in ys) for left in xs)
    return rounds, mds


def poseidon_hash2(first: int, second: int) -> int:
    rounds, mds = _poseidon_constants()
    state = [first, second, 2 << 64]
    for round_index, constants in enumerate(rounds):
        state = [(value + constant) % PASTA_FP_MODULUS
                 for value, constant in zip(state, constants)]
        if round_index < 4 or round_index >= 60:
            state = [pow(value, 5, PASTA_FP_MODULUS) for value in state]
        else:
            state[0] = pow(state[0], 5, PASTA_FP_MODULUS)
        state = [sum(mds[row][column] * state[column] for column in range(3)) % PASTA_FP_MODULUS
                 for row in range(3)]
    return state[0]


class Lowerer:
    def __init__(self, function_names: dict[str, Function], limits: dict, current_function: str,
                 records: dict[str, Type]):
        self.function_names = function_names
        self.limits = limits
        self.current_function = current_function
        self.records = records
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
        if expression.kind == "bytes":
            if expected is None or expected.name != "bytes" or len(expression.value) != expected.length:
                raise CompileError("E_BYTES_LITERAL", "byte-string literal length differs from its context")
            return expected, self.emit("bytes", expected, text=bytes(expression.value).hex())
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
            if name not in self.function_names:
                raise CompileError("E_CALL_ORDER", "direct call target is not in the closed function set")
            if len(target.parameters) != len(expression.args):
                raise CompileError("E_CALL_ARITY", f"wrong argument count for {name}")
            operands = []
            for argument, parameter in zip(expression.args, target.parameters):
                actual, value = self.expression(argument, parameter.type)
                if actual != parameter.type:
                    raise CompileError("E_CALL_TYPE", f"wrong argument type for {name}")
                operands.append(value)
            return target.return_type, self.emit("call", target.return_type, operands, text=name)
        if expression.kind == "array":
            if expected is None or expected.element is None or len(expression.args) != expected.length:
                raise CompileError("E_ARRAY_TYPE", "array literal requires an exact fixed-array context")
            operands = []
            for element in expression.args:
                actual, value = self.expression(element, expected.element)
                if actual != expected.element:
                    raise CompileError("E_ARRAY_ELEMENT", "array element type differs from its context")
                operands.append(value)
            return expected, self.emit("array", expected, operands)
        if expression.kind == "index":
            array_type, array = self.expression(expression.args[0])
            if array_type.element is None:
                raise CompileError("E_INDEX_TYPE", "indexing requires a fixed array")
            index_type, index = self.expression(expression.args[1], Type("u64"))
            if index_type.name != "u64":
                raise CompileError("E_INDEX_TYPE", "array index requires u64")
            return array_type.element, self.emit("index", array_type.element, (array, index), immediate=array_type.length)
        if expression.kind == "record":
            record_name, field_names = expression.value
            record_type = self.records.get(record_name)
            if record_type is None or expected != record_type:
                raise CompileError("E_RECORD_TYPE", "record literal requires its exact declared context")
            if tuple(name for name, _ in record_type.fields) != field_names:
                raise CompileError("E_RECORD_FIELDS", "record literal fields are missing, reordered or unknown")
            operands = []
            for expression_value, (_, field_type) in zip(expression.args, record_type.fields):
                actual, value = self.expression(expression_value, field_type)
                if actual != field_type:
                    raise CompileError("E_RECORD_FIELD_TYPE", "record field type differs")
                operands.append(value)
            return record_type, self.emit("record", record_type, operands)
        if expression.kind == "field":
            record_type, record = self.expression(expression.args[0])
            if record_type.name != "record":
                raise CompileError("E_FIELD_TYPE", "field access requires a record")
            matches = [(index, type_) for index, (name, type_) in enumerate(record_type.fields)
                       if name == expression.value]
            if len(matches) != 1:
                raise CompileError("E_FIELD_NAME", f"unknown record field {expression.value!r}")
            index, field_type = matches[0]
            return field_type, self.emit("field", field_type, (record,), immediate=index)
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
    "add", "sub", "mul", "div", "rem", "shl", "shr", "bytes", "array", "index", "record", "field", "intrinsic", "call", "assert", "return"
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
        "dependency_format": "content-addressed-onyx-library-v1",
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
    records = {}
    for dependency in package.dependencies:
        for relative, data in dependency.sources:
            parsed = Parser(lex(data, f"dependency/{dependency.name}/{relative}"),
                            f"dependency/{dependency.name}/{relative}", records).parse()
            if any(function.exported for function in parsed):
                raise CompileError("E_LIBRARY_EXPORT", "dependency functions cannot be transaction exports")
            prefix = dependency.name.replace("-", "_") + "__"
            if any(not function.name.startswith(prefix) for function in parsed):
                raise CompileError("E_LIBRARY_NAMESPACE",
                    f"dependency functions must use the namespace prefix {prefix!r}")
            functions.extend(parsed)
    for path, data in package.sources:
        functions.extend(Parser(lex(data, path), path, records).parse())
    if not functions:
        raise CompileError("E_FUNCTION_COUNT", "package contains no functions")
    names = [function.name for function in functions]
    if len(names) != len(set(names)):
        raise CompileError("E_FUNCTION_ORDER", "functions must be globally unique")
    mapping = {function.name: function for function in functions}
    actual_exports = sorted(function.name for function in functions if function.exported)
    if actual_exports != package.manifest["exports"]:
        raise CompileError("E_EXPORT_MISMATCH", "manifest exports differ from source exports")
    dependencies = {name: function_calls(function) for name, function in mapping.items()}
    for name, calls in dependencies.items():
        unknown = calls - mapping.keys()
        if unknown:
            raise CompileError("E_UNKNOWN_CALL", f"{name} calls unknown functions: {sorted(unknown)}")
    ordered = []
    remaining = set(mapping)
    while remaining:
        available = sorted(name for name in remaining if dependencies[name].isdisjoint(remaining))
        if not available:
            raise CompileError("E_CALL_CYCLE", "function call graph is recursive")
        for name in available:
            ordered.append(mapping[name])
            remaining.remove(name)
    functions = ordered
    compiled = [Lowerer(mapping, package.manifest["limits"], function.name, records).lower(function)
                for function in functions]
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
                if instruction.opcode == "intrinsic":
                    cost = 1 + INTRINSICS[instruction.text][2]
                elif instruction.opcode == "array":
                    cost = 1 + len(instruction.operands)
                elif instruction.opcode == "index":
                    cost = 1 + 2 * int(instruction.immediate or 0)
                elif instruction.opcode == "record":
                    cost = 1 + len(instruction.operands)
                elif instruction.opcode == "bytes":
                    cost = 1 + len(instruction.text) // 2
                else:
                    cost = 1
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


def function_calls(function: Function) -> set[str]:
    result = set()
    def expression_calls(expression: Expr | None):
        if expression is None:
            return
        if expression.kind == "call" and expression.value not in INTRINSICS:
            result.add(str(expression.value))
        for argument in expression.args:
            expression_calls(argument)
    def statement_calls(statements: tuple[Statement, ...]):
        for statement in statements:
            expression_calls(statement.expression)
            statement_calls(statement.body)
            statement_calls(statement.alternate)
    statement_calls(function.body)
    return result


PASTA_FP_MODULUS = int("40000000000000000000000000000000224698fc094cf91b992d30ed00000001", 16)


class ExecutionFailure(RuntimeError):
    pass


class UnsupportedEvaluation(RuntimeError):
    pass


def neutral_value(type_name: str):
    match = re.fullmatch(r"\[(.+);([1-9][0-9]{0,3})\]", type_name)
    if match:
        return tuple(neutral_value(match.group(1)) for _ in range(int(match.group(2))))
    if type_name.startswith("{"):
        return tuple(neutral_value(type_) for _, type_ in parse_record_type(type_name))
    match = re.fullmatch(r"bytes<([1-9][0-9]{0,3})>", type_name)
    if match:
        return bytes(int(match.group(1)))
    return False if type_name == "bool" else 0


def checked_value(value, type_name: str):
    if type_name == "bool":
        if type(value) is not bool:
            raise ExecutionFailure("expected bool")
        return value
    if type_name in INTEGER_BITS:
        if type(value) is not int or value < 0 or value >= 1 << INTEGER_BITS[type_name]:
            raise ExecutionFailure(f"value is outside {type_name}")
        return value
    if type_name == "field":
        if type(value) is not int or value < 0 or value >= PASTA_FP_MODULUS:
            raise ExecutionFailure("value is outside the Pasta base field")
        return value
    match = re.fullmatch(r"bytes<([1-9][0-9]{0,3})>", type_name)
    if match:
        length = int(match.group(1))
        if isinstance(value, str):
            if not re.fullmatch(r"[0-9a-f]*", value) or len(value) != length * 2:
                raise ExecutionFailure("byte-string hex value is not canonical")
            return bytes.fromhex(value)
        if not isinstance(value, bytes) or len(value) != length:
            raise ExecutionFailure("byte-string value has the wrong length")
        return value
    match = re.fullmatch(r"\[(.+);([1-9][0-9]{0,3})\]", type_name)
    if match:
        if not isinstance(value, (list, tuple)) or len(value) != int(match.group(2)):
            raise ExecutionFailure("fixed-array value has the wrong length")
        return tuple(checked_value(item, match.group(1)) for item in value)
    if type_name.startswith("{"):
        fields = parse_record_type(type_name)
        if not isinstance(value, (list, tuple)) or len(value) != len(fields):
            raise ExecutionFailure("record value has the wrong field count")
        return tuple(checked_value(item, field_type) for item, (_, field_type) in zip(value, fields))
    raise ExecutionFailure(f"reference evaluator does not support {type_name}")


def evaluate_function(function: CompiledFunction, inputs: list, functions: dict[str, CompiledFunction]):
    if len(inputs) != len(function.source.parameters):
        raise ExecutionFailure("input arity mismatch")
    typed_inputs = [checked_value(value, parameter.type.canonical())
                    for value, parameter in zip(inputs, function.source.parameters)]
    input_index = 0
    values = {}
    result = None
    for index, instruction in enumerate(function.instructions):
        active = instruction.guard is None or bool(values[instruction.guard])
        operands = [values[operand] for operand in instruction.operands]
        if instruction.opcode == "parameter":
            value = typed_inputs[input_index]
            input_index += 1
        elif not active:
            value = neutral_value(instruction.type)
        elif instruction.opcode == "const":
            value = checked_value(bool(instruction.immediate) if instruction.type == "bool" else instruction.immediate,
                                  instruction.type)
        elif instruction.opcode == "bytes":
            value = checked_value(instruction.text, instruction.type)
        elif instruction.opcode == "not":
            value = not operands[0]
        elif instruction.opcode == "and":
            value = operands[0] and operands[1]
        elif instruction.opcode == "or":
            value = operands[0] or operands[1]
        elif instruction.opcode in ("eq", "ne", "lt", "le", "gt", "ge"):
            value = {"eq": operands[0] == operands[1], "ne": operands[0] != operands[1],
                     "lt": operands[0] < operands[1], "le": operands[0] <= operands[1],
                     "gt": operands[0] > operands[1], "ge": operands[0] >= operands[1]}[instruction.opcode]
        elif instruction.opcode in ("add", "sub", "mul", "div", "rem", "shl", "shr"):
            left, right = operands
            if instruction.opcode in ("div", "rem") and right == 0:
                raise ExecutionFailure("division by zero")
            if instruction.opcode in ("shl", "shr") and right >= INTEGER_BITS[instruction.type]:
                raise ExecutionFailure("shift count exceeds integer width")
            if instruction.opcode == "add": value = left + right
            elif instruction.opcode == "sub": value = left - right
            elif instruction.opcode == "mul": value = left * right
            elif instruction.opcode == "div":
                value = (left * pow(right, -1, PASTA_FP_MODULUS)) % PASTA_FP_MODULUS if instruction.type == "field" else left // right
            elif instruction.opcode == "rem": value = left % right
            elif instruction.opcode == "shl": value = left << right
            else: value = left >> right
            if instruction.type == "field":
                value %= PASTA_FP_MODULUS
            value = checked_value(value, instruction.type)
        elif instruction.opcode == "array":
            value = checked_value(operands, instruction.type)
        elif instruction.opcode == "index":
            if operands[1] >= int(instruction.immediate):
                raise ExecutionFailure("array index exceeds its bound")
            value = operands[0][operands[1]]
        elif instruction.opcode == "record":
            value = checked_value(operands, instruction.type)
        elif instruction.opcode == "field":
            value = operands[0][int(instruction.immediate)]
        elif instruction.opcode == "call":
            value = evaluate_function(functions[instruction.text], operands, functions)
        elif instruction.opcode == "intrinsic":
            if instruction.text == "poseidon_hash":
                value = poseidon_hash2(operands[0], operands[1])
            elif instruction.text == "merkle_root":
                value = poseidon_hash2(2, poseidon_hash2(operands[0], operands[1]))
            elif instruction.text == "nullifier":
                value = poseidon_hash2(3, poseidon_hash2(poseidon_hash2(
                    operands[0], operands[1]), operands[2]))
            else:
                raise UnsupportedEvaluation("reference evaluator has no intrinsic backend")
        elif instruction.opcode == "assert":
            if not operands[0]:
                raise ExecutionFailure("assertion failed")
            continue
        elif instruction.opcode == "return":
            result = checked_value(operands[0], instruction.type)
            continue
        else:
            raise ExecutionFailure("unknown evaluator opcode")
        if instruction.result is not None:
            values[index] = checked_value(value, instruction.type)
    if result is None:
        raise ExecutionFailure("function produced no result")
    return result


def evaluate_vectors(package: SourcePackage, compiled: list[CompiledFunction]) -> dict:
    functions = {function.source.name: function for function in compiled}
    results = []
    for number, vector in enumerate(package.manifest["vectors"]):
        try:
            result = evaluate_function(functions[vector["function"]], vector["inputs"], functions)
        except UnsupportedEvaluation as error:
            raise CompileError("E_VECTOR_UNSUPPORTED", f"vector {number} cannot be evaluated: {error}") from error
        except ExecutionFailure as error:
            if vector.get("expect_failure") is not True:
                raise CompileError("E_VECTOR_EXECUTION", f"positive vector {number} failed: {error}") from error
            results.append({"function": vector["function"], "inputs": vector["inputs"],
                            "outcome": "rejected"})
            continue
        if vector.get("expect_failure") is True:
            raise CompileError("E_VECTOR_ACCEPTED", f"negative vector {number} unexpectedly succeeded")
        expected = checked_value(vector["expected"], functions[vector["function"]].source.return_type.canonical())
        if result != expected:
            raise CompileError("E_VECTOR_RESULT", f"positive vector {number} result mismatch")
        results.append({"function": vector["function"], "inputs": vector["inputs"],
                        "outcome": "accepted", "result": json_value(result)})
    return {"format": 1, "reference": "checked-onyx-ir-v1", "vectors": results}


def json_value(value):
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, tuple):
        return [json_value(item) for item in value]
    return value


def parse_record_type(value: str) -> tuple[tuple[str, str], ...]:
    if not value.startswith("{") or not value.endswith("}"):
        raise ExecutionFailure("invalid record type")
    body = value[1:-1]
    fields = []
    start = 0
    depth = 0
    parts = []
    for index, character in enumerate(body):
        if character in "[{": depth += 1
        elif character in "]}": depth -= 1
        elif character == "," and depth == 0:
            parts.append(body[start:index]); start = index + 1
    parts.append(body[start:])
    for part in parts:
        name, separator, type_name = part.partition(":")
        if not separator or not name or not type_name:
            raise ExecutionFailure("invalid record type")
        fields.append((name, type_name))
    return tuple(fields)


def backend_descriptor(executable: pathlib.Path, ir: bytes, circuit_k: int, export: str) -> bytes:
    executable = executable.resolve()
    if not executable.is_file() or executable.is_symlink():
        raise CompileError("E_BACKEND_EXECUTABLE", "Halo2 backend executable is missing or linked")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", export):
        raise CompileError("E_BACKEND_EXPORT", "Halo2 backend export is not an identifier")
    try:
        process = subprocess.run([str(executable), "descriptor", str(circuit_k), export], input=ir,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, check=False)
    except subprocess.TimeoutExpired as error:
        raise CompileError("E_BACKEND_TIMEOUT", "Halo2 backend descriptor generation timed out") from error
    except OSError as error:
        raise CompileError("E_BACKEND_EXECUTION", "Halo2 backend could not be executed") from error
    if process.returncode != 0:
        message = process.stderr.decode("utf-8", "replace")[:512]
        raise CompileError("E_BACKEND_REJECTED", f"Halo2 backend rejected canonical IR: {message}")
    output = process.stdout.strip()
    if not re.fullmatch(b"[0-9a-f]{266}", output):
        raise CompileError("E_BACKEND_DESCRIPTOR", "Halo2 backend descriptor is not canonical v2 hex")
    descriptor = bytes.fromhex(output.decode("ascii"))
    export_digest = hashlib.sha256(EXPORT_ID_DOMAIN + len(export.encode("ascii")).to_bytes(8, "little") +
                                   export.encode("ascii")).digest()
    if (descriptor[0] != 2 or int.from_bytes(descriptor[1:5], "little") != circuit_k or
            descriptor[5:37] != ir[len(IR_DOMAIN):len(IR_DOMAIN) + 32] or
            descriptor[37:69] != hashlib.sha256(ir).digest() or descriptor[69:101] != export_digest):
        raise CompileError("E_BACKEND_DESCRIPTOR", "Halo2 backend descriptor header mismatch")
    return descriptor


def write_bundle(package: SourcePackage, destination: pathlib.Path,
                 backend_executable: pathlib.Path | None = None, circuit_k: int = 12) -> None:
    if os.path.lexists(destination):
        raise CompileError("E_OUTPUT_EXISTS", "output path already exists")
    compiled, ir, metadata, schemas = compile_sources(package)
    vectors = evaluate_vectors(package, compiled)
    descriptors = None
    if backend_executable is not None:
        descriptors = {export: backend_descriptor(backend_executable, ir, circuit_k, export)
                       for export in package.manifest["exports"]}
        metadata["resources"]["backend_measurements"] = {
            "backend": "halo2-ipa-pasta-compiler-alpha",
            "circuit_k": circuit_k,
            "descriptor_bytes": {name: len(descriptor) for name, descriptor in descriptors.items()},
        }
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
        if package.dependencies:
            (temporary / "dependencies").mkdir()
        for dependency in package.dependencies:
            dependency_output = temporary / "dependencies" / dependency.digest
            dependency_output.mkdir()
            (dependency_output / "onyx-library.json").write_bytes(dependency.manifest_bytes)
            for relative, data in dependency.sources:
                output = dependency_output / relative
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_bytes(data)
        (temporary / "program.onxir").write_bytes(ir)
        ir_id = sha256(IR_ID_DOMAIN + ir)
        (temporary / "ir-id.txt").write_bytes((ir_id + "\n").encode("ascii"))
        (temporary / "target-profile.json").write_bytes(canonical_json(metadata["profile"]))
        (temporary / "resources.json").write_bytes(canonical_json(metadata["resources"]))
        (temporary / "vectors.json").write_bytes(canonical_json(vectors))
        if descriptors is not None:
            descriptor_directory = temporary / "halo2-vk-descriptors"
            descriptor_directory.mkdir()
            for name, descriptor in descriptors.items():
                (descriptor_directory / f"{name}.bin").write_bytes(descriptor)
        for name, schema in schemas.items():
            (temporary / "schemas" / f"{name}.json").write_bytes(canonical_json(schema))
        provenance = {
            "format": 1,
            "compiler_version": COMPILER_VERSION,
            "compiler_build_digest": compiler_digest(),
            "package_manifest_sha256": sha256(package.manifest_bytes),
            "dependency_lock_sha256": sha256(package.lock_bytes),
            "dependencies": [{"name": dependency.name, "version": dependency.version,
                              "artifact_sha256": dependency.digest} for dependency in package.dependencies],
            "target_profile_sha256": sha256(canonical_json(metadata["profile"])),
            "ir_id": ir_id,
            "registrable": False,
            "missing_gate": "audited deterministic Halo2 lowering and verifying-key regeneration",
        }
        if descriptors is not None:
            provenance["halo2_backend"] = {
                "circuit_k": circuit_k,
                "descriptor_sha256": {name: sha256(descriptor)
                                      for name, descriptor in descriptors.items()},
                "status": "compiler-alpha-not-registrable",
            }
        (temporary / "provenance.json").write_bytes(canonical_json(provenance))
        files = []
        for path in sorted((path for path in temporary.rglob("*") if path.is_file()), key=lambda item: item.relative_to(temporary).as_posix().encode("utf-8")):
            relative = path.relative_to(temporary).as_posix()
            files.append({"path": relative, "sha256": sha256(path.read_bytes()), "size": path.stat().st_size})
        (temporary / "SHA256MANIFEST.json").write_bytes(canonical_json({"format": 1, "files": files}))
        if os.path.lexists(destination):
            raise CompileError("E_OUTPUT_EXISTS", "output path already exists")
        os.replace(temporary, destination)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("package", nargs="?", type=pathlib.Path)
    parser.add_argument("output", nargs="?", type=pathlib.Path)
    parser.add_argument("--dependency-store", type=pathlib.Path)
    parser.add_argument("--backend-executable", type=pathlib.Path)
    parser.add_argument("--circuit-k", type=int, default=12)
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
        write_bundle(load_package(args.package, args.dependency_store), args.output,
                     args.backend_executable, args.circuit_k)
    except CompileError as error:
        print(error)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
