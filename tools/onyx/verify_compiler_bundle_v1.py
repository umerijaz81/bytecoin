#!/usr/bin/env python3
"""Strict independent decoder and reproducibility verifier for Onyx frontend v1 bundles."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import shutil
import tempfile

import compiler_v1


class VerificationError(RuntimeError):
    pass


def canonical_json(value: object) -> bytes:
    return compiler_v1.canonical_json(value)


class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def take(self, count: int) -> bytes:
        if count < 0 or count > len(self.data) - self.offset:
            raise VerificationError("truncated canonical IR")
        result = self.data[self.offset:self.offset + count]
        self.offset += count
        return result

    def byte(self) -> int:
        return self.take(1)[0]

    def uleb(self) -> int:
        result = 0
        shift = 0
        encoded = bytearray()
        while True:
            byte = self.byte()
            encoded.append(byte)
            if shift >= 64 and byte & 0x7F:
                raise VerificationError("IR integer exceeds u64")
            result |= (byte & 0x7F) << shift
            if not byte & 0x80:
                break
            shift += 7
            if len(encoded) > 10:
                raise VerificationError("IR integer is overlong")
        if result > compiler_v1.U64_MAX or bytes(encoded) != compiler_v1.uleb(result):
            raise VerificationError("IR integer is not shortest-form uLEB128")
        return result

    def text(self, maximum: int = 4096) -> str:
        length = self.uleb()
        if length > maximum:
            raise VerificationError("IR text exceeds its bound")
        try:
            result = self.take(length).decode("utf-8")
        except UnicodeDecodeError as error:
            raise VerificationError("IR text is not strict UTF-8") from error
        if compiler_v1.unicodedata.normalize("NFC", result) != result:
            raise VerificationError("IR text is not Unicode NFC")
        return result


def valid_type(value: str) -> bool:
    if value in ("bool", "u8", "u16", "u32", "u64", "field"):
        return True
    match = compiler_v1.re.fullmatch(r"bytes<([1-9][0-9]{0,3})>", value)
    if match:
        return int(match.group(1)) <= 4096
    match = compiler_v1.re.fullmatch(r"\[(.+);([1-9][0-9]{0,3})\]", value)
    if match:
        return bool(int(match.group(2)) <= compiler_v1.MAX_LOOP_BOUND and valid_type(match.group(1)))
    if value.startswith("{"):
        fields = record_type(value)
        return fields is not None and bool(fields)
    return False


def array_type(value: str) -> tuple[str, int] | None:
    match = compiler_v1.re.fullmatch(r"\[(.+);([1-9][0-9]{0,3})\]", value)
    if not match or not valid_type(match.group(1)):
        return None
    return match.group(1), int(match.group(2))


def record_type(value: str) -> tuple[tuple[str, str], ...] | None:
    if not value.startswith("{") or not value.endswith("}"):
        return None
    body = value[1:-1]
    start = 0
    depth = 0
    parts = []
    for index, character in enumerate(body):
        if character in "[{": depth += 1
        elif character in "]}":
            depth -= 1
            if depth < 0: return None
        elif character == "," and depth == 0:
            parts.append(body[start:index]); start = index + 1
    if depth != 0: return None
    parts.append(body[start:])
    fields = []
    for part in parts:
        name, separator, field_type = part.partition(":")
        if not separator or not compiler_v1.re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) or not valid_type(field_type):
            return None
        fields.append((name, field_type))
    if [name for name, _ in fields] != sorted(set(name for name, _ in fields)):
        return None
    return tuple(fields)


def verify_ir(data: bytes, profile: dict, resources: dict) -> None:
    reader = Reader(data)
    if reader.take(len(compiler_v1.IR_DOMAIN)) != compiler_v1.IR_DOMAIN:
        raise VerificationError("IR domain/version mismatch")
    if reader.take(32) != hashlib.sha256(canonical_json(profile)).digest():
        raise VerificationError("IR target-profile digest mismatch")
    function_count = reader.uleb()
    if not 0 < function_count <= 1024:
        raise VerificationError("IR function count is outside bounds")
    function_names = set()
    total_instructions = 0
    public_inputs = 0
    private_inputs = 0
    reverse_opcodes = {value: key for key, value in compiler_v1.OPCODES.items()}
    signatures = {}
    expanded_weights = {}
    constraint_weights = {}
    total_expanded = 0
    total_constraints = 0
    for _ in range(function_count):
        name = reader.text(128)
        if not compiler_v1.re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) or name in function_names:
            raise VerificationError("IR function name is invalid or duplicated")
        function_names.add(name)
        if reader.byte() not in (0, 1):
            raise VerificationError("invalid IR export flag")
        parameter_count = reader.uleb()
        if parameter_count > 4096:
            raise VerificationError("IR parameter count exceeds bound")
        parameter_names = set()
        parameter_types = []
        parameter_specs = []
        for _ in range(parameter_count):
            visibility = reader.byte()
            if visibility == 1:
                public_inputs += 1
            elif visibility == 2:
                private_inputs += 1
            else:
                raise VerificationError("invalid IR parameter visibility")
            parameter_name = reader.text(128)
            if parameter_name in parameter_names or not compiler_v1.re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", parameter_name):
                raise VerificationError("invalid or duplicate IR parameter")
            parameter_names.add(parameter_name)
            parameter_type = reader.text(128)
            if not valid_type(parameter_type):
                raise VerificationError("invalid IR parameter type")
            parameter_types.append(parameter_type)
            parameter_specs.append(("public" if visibility == 1 else "private", parameter_name, parameter_type))
        return_type = reader.text(128)
        if not valid_type(return_type):
            raise VerificationError("invalid IR return type")
        instruction_count = reader.uleb()
        if not 0 < instruction_count <= compiler_v1.MAX_INSTRUCTIONS:
            raise VerificationError("IR instruction count exceeds bound")
        total_instructions += instruction_count
        saw_return = False
        function_expanded = 0
        function_constraints = 0
        value_types = {}
        for index in range(instruction_count):
            opcode_number = reader.byte()
            if opcode_number not in reverse_opcodes:
                raise VerificationError("unknown IR opcode")
            opcode = reverse_opcodes[opcode_number]
            encoded_result = reader.uleb()
            result = None if encoded_result == 0 else encoded_result - 1
            type_name = reader.text(128)
            if not valid_type(type_name):
                raise VerificationError("invalid IR instruction type")
            operand_count = reader.uleb()
            if operand_count > 64:
                raise VerificationError("IR instruction operand count exceeds bound")
            operands = [reader.uleb() for _ in range(operand_count)]
            if any(operand >= index for operand in operands):
                raise VerificationError("IR operand does not dominate its use")
            encoded_guard = reader.uleb()
            guard = None if encoded_guard == 0 else encoded_guard - 1
            if guard is not None and (guard >= index or guard not in value_types or value_types[guard] != "bool"):
                raise VerificationError("IR guard is not a dominating boolean value")
            encoded_immediate = reader.uleb()
            immediate = None if encoded_immediate == 0 else encoded_immediate - 1
            text = reader.text(8192)
            side_effect = opcode in ("assert", "return")
            if side_effect != (result is None) or (result is not None and result != index):
                raise VerificationError("IR result numbering is not canonical SSA order")
            if opcode == "parameter" and (operands or guard is not None or immediate is not None or not text.startswith(("public:", "private:"))):
                raise VerificationError("malformed IR parameter")
            if opcode == "const" and (operands or immediate is None or text):
                raise VerificationError("malformed IR constant")
            if opcode == "intrinsic" and text not in compiler_v1.INTRINSICS:
                raise VerificationError("unknown IR intrinsic")
            if opcode == "call" and (not compiler_v1.re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", text) or text not in signatures):
                raise VerificationError("IR direct call does not target an earlier function")
            if opcode not in ("parameter", "bytes", "intrinsic", "call") and text:
                raise VerificationError("unexpected IR instruction text")
            if opcode not in ("const", "index", "field") and immediate is not None:
                raise VerificationError("unexpected IR immediate")
            if opcode == "return":
                if saw_return or index + 1 != instruction_count or len(operands) != 1:
                    raise VerificationError("return is not the unique final instruction")
                saw_return = True
            expected_operands = {
                "parameter": 0, "const": 0, "not": 1, "and": 2, "or": 2, "eq": 2,
                "ne": 2, "lt": 2, "le": 2, "gt": 2, "ge": 2, "add": 2, "sub": 2,
                "mul": 2, "div": 2, "rem": 2, "shl": 2, "shr": 2, "return": 1,
                "index": 2,
                "field": 1,
                "bytes": 0,
            }
            if opcode in expected_operands and len(operands) != expected_operands[opcode]:
                raise VerificationError("IR opcode has a noncanonical operand count")
            if opcode == "assert" and len(operands) != 1:
                raise VerificationError("IR assertion has a noncanonical operand count")
            if opcode == "intrinsic" and len(operands) != len(compiler_v1.INTRINSICS[text][0]):
                raise VerificationError("IR intrinsic has a noncanonical operand count")
            if opcode == "call":
                if text not in signatures or len(operands) != len(signatures[text][0]) or type_name != signatures[text][1]:
                    raise VerificationError("IR call differs from its earlier target signature")
                if tuple(value_types[operand] for operand in operands) != signatures[text][0]:
                    raise VerificationError("IR call operand types differ from its target signature")
                function_expanded += expanded_weights[text]
                function_constraints += constraint_weights[text]
            else:
                function_expanded += 1
                if opcode == "intrinsic":
                    function_constraints += 1 + compiler_v1.INTRINSICS[text][2]
                elif opcode == "array":
                    function_constraints += 1 + len(operands)
                elif opcode == "index":
                    function_constraints += 1 + 2 * int(immediate or 0)
                elif opcode == "record":
                    function_constraints += 1 + len(operands)
                elif opcode == "bytes":
                    function_constraints += 1 + len(text) // 2
                else:
                    function_constraints += 1
            operand_types = tuple(value_types[operand] for operand in operands)
            if opcode == "parameter":
                if index >= len(parameter_specs) or (text, type_name) != (
                        parameter_specs[index][0] + ":" + parameter_specs[index][1], parameter_specs[index][2]):
                    raise VerificationError("IR parameter instruction differs from the declared signature")
            elif opcode == "const":
                if type_name == "bool" and immediate not in (0, 1):
                    raise VerificationError("IR boolean constant is noncanonical")
                if type_name in compiler_v1.INTEGER_BITS and immediate >= 1 << compiler_v1.INTEGER_BITS[type_name]:
                    raise VerificationError("IR integer constant exceeds its type")
            elif opcode == "bytes":
                match = compiler_v1.re.fullmatch(r"bytes<([1-9][0-9]{0,3})>", type_name)
                if match is None or not compiler_v1.re.fullmatch(r"[0-9a-f]*", text) or len(text) != int(match.group(1)) * 2:
                    raise VerificationError("IR byte-string literal is invalid")
            elif opcode == "not" and (operand_types != ("bool",) or type_name != "bool"):
                raise VerificationError("IR logical-not types are invalid")
            elif opcode in ("and", "or") and (operand_types != ("bool", "bool") or type_name != "bool"):
                raise VerificationError("IR boolean operator types are invalid")
            elif opcode in ("add", "sub", "mul", "div", "rem", "shl", "shr"):
                if len(set(operand_types + (type_name,))) != 1 or type_name not in (*compiler_v1.INTEGER_BITS, "field"):
                    raise VerificationError("IR arithmetic types are invalid")
                if type_name == "field" and opcode in ("rem", "shl", "shr"):
                    raise VerificationError("IR field operator is invalid")
            elif opcode in ("eq", "ne", "lt", "le", "gt", "ge"):
                if len(operand_types) != 2 or operand_types[0] != operand_types[1] or type_name != "bool":
                    raise VerificationError("IR comparison types are invalid")
                if operand_types[0] == "field" and opcode not in ("eq", "ne"):
                    raise VerificationError("IR field ordering is invalid")
            elif opcode == "intrinsic":
                expected_parameters, expected_result, _ = compiler_v1.INTRINSICS[text]
                if operand_types != expected_parameters or type_name != expected_result:
                    raise VerificationError("IR intrinsic types are invalid")
            elif opcode == "array":
                parsed_array = array_type(type_name)
                if parsed_array is None or len(operand_types) != parsed_array[1] or any(
                        operand_type != parsed_array[0] for operand_type in operand_types):
                    raise VerificationError("IR array construction types are invalid")
            elif opcode == "index":
                parsed_array = array_type(operand_types[0]) if len(operand_types) == 2 else None
                if parsed_array is None or operand_types[1] != "u64" or type_name != parsed_array[0] or immediate != parsed_array[1]:
                    raise VerificationError("IR bounded-index types are invalid")
            elif opcode == "record":
                fields = record_type(type_name)
                if fields is None or operand_types != tuple(field_type for _, field_type in fields):
                    raise VerificationError("IR record construction types are invalid")
            elif opcode == "field":
                fields = record_type(operand_types[0]) if len(operand_types) == 1 else None
                if fields is None or immediate is None or immediate >= len(fields) or type_name != fields[immediate][1]:
                    raise VerificationError("IR record field access is invalid")
            elif opcode == "assert" and (type_name != "bool" or any(value != "bool" for value in operand_types)):
                raise VerificationError("IR assertion types are invalid")
            elif opcode == "return" and (operand_types != (return_type,) or type_name != return_type):
                raise VerificationError("IR return type is invalid")
            if opcode == "return" and guard is not None:
                raise VerificationError("IR return cannot be conditionally guarded")
            if result is not None:
                value_types[result] = type_name
        if not saw_return:
            raise VerificationError("IR function has no return")
        signatures[name] = (tuple(parameter_types), return_type)
        expanded_weights[name] = function_expanded
        constraint_weights[name] = function_constraints
        total_expanded += function_expanded
        total_constraints += function_constraints
    if reader.offset != len(data):
        raise VerificationError("IR has trailing bytes")
    if total_instructions != resources.get("ir_instructions") or function_count != resources.get("functions"):
        raise VerificationError("resource report differs from decoded IR")
    if total_expanded != resources.get("expanded_instructions") or total_constraints != resources.get("constraints_upper_bound"):
        raise VerificationError("expanded resource report differs from decoded call graph")
    if public_inputs != resources.get("public_inputs") or private_inputs != resources.get("private_inputs"):
        raise VerificationError("resource input counts differ from decoded IR")
    rows = total_constraints + function_count * 8
    advice_columns = 3
    fixed_columns = 2
    instance_columns = 1 if public_inputs else 0
    expected_resources = {
        "rows_upper_bound": rows,
        "advice_columns_upper_bound": advice_columns,
        "fixed_columns_upper_bound": fixed_columns,
        "instance_columns_upper_bound": instance_columns,
        "witness_bytes_upper_bound": private_inputs * 32 + total_expanded * 32,
        "proving_memory_bytes_upper_bound": rows * (advice_columns + fixed_columns + instance_columns) * 32,
        "lookups_upper_bound": 0,
        "verifier_work_upper_bound": total_constraints + public_inputs * 2,
        "proof_bytes_upper_bound": 1024 + advice_columns * 64 + public_inputs * 32 + (total_constraints + 7) // 8,
    }
    for field, expected in expected_resources.items():
        if resources.get(field) != expected:
            raise VerificationError(f"resource formula mismatch: {field}")


def read_json(path: pathlib.Path, maximum: int = 1 << 20) -> tuple[object, bytes]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise VerificationError(f"missing, linked or oversized file: {path.name}")
    data = path.read_bytes()
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"invalid JSON: {path.name}") from error
    if canonical_json(value) != data:
        raise VerificationError(f"noncanonical JSON: {path.name}")
    return value, data


def compare_directories(first: pathlib.Path, second: pathlib.Path) -> None:
    first_files = sorted(path.relative_to(first).as_posix() for path in first.rglob("*") if path.is_file())
    second_files = sorted(path.relative_to(second).as_posix() for path in second.rglob("*") if path.is_file())
    if first_files != second_files:
        raise VerificationError("recompiled bundle file set differs")
    for relative in first_files:
        if (first / relative).read_bytes() != (second / relative).read_bytes():
            raise VerificationError(f"recompiled artifact differs: {relative}")


def verify_bundle(root: pathlib.Path) -> None:
    root = root.resolve()
    if not root.is_dir() or root.is_symlink():
        raise VerificationError("bundle root is not a regular directory")
    manifest, manifest_bytes = read_json(root / "SHA256MANIFEST.json")
    if not isinstance(manifest, dict) or set(manifest) != {"format", "files"} or manifest["format"] != 1:
        raise VerificationError("invalid artifact manifest schema")
    entries = manifest["files"]
    if not isinstance(entries, list) or not entries:
        raise VerificationError("empty artifact manifest")
    expected = []
    previous = b""
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "size"}:
            raise VerificationError("invalid artifact manifest entry")
        relative = compiler_v1.validate_path(entry["path"])
        encoded = relative.encode("utf-8")
        if previous and encoded <= previous:
            raise VerificationError("artifact manifest is not UTF-8 byte sorted")
        previous = encoded
        path = root.joinpath(*relative.split("/"))
        if path.is_symlink() or not path.is_file() or root not in path.resolve().parents:
            raise VerificationError(f"unsafe artifact path: {relative}")
        data = path.read_bytes()
        if len(data) != entry["size"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise VerificationError(f"artifact digest mismatch: {relative}")
        expected.append(relative)
    actual = sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file() and path.name != "SHA256MANIFEST.json")
    if actual != expected:
        raise VerificationError("bundle contains unmanifested or missing files")
    profile, _ = read_json(root / "target-profile.json")
    resources, _ = read_json(root / "resources.json")
    provenance, _ = read_json(root / "provenance.json")
    if not isinstance(profile, dict) or profile.get("backend_status") != "frontend-only-not-registrable":
        raise VerificationError("bundle target profile is not the fail-closed frontend profile")
    if not isinstance(resources, dict) or resources.get("backend_measurements", "missing") is not None:
        raise VerificationError("frontend resource report claims backend measurements")
    if not isinstance(provenance, dict) or provenance.get("registrable") is not False:
        raise VerificationError("frontend bundle incorrectly claims registrability")
    lock, lock_bytes = read_json(root / "source" / "onyx.lock")
    if provenance.get("dependency_lock_sha256") != hashlib.sha256(lock_bytes).hexdigest() or \
            provenance.get("dependencies") != lock.get("dependencies"):
        raise VerificationError("dependency provenance differs from the normalized lock")
    dependency_root = root / "dependencies"
    expected_dependency_digests = [entry["artifact_sha256"] for entry in lock.get("dependencies", [])]
    actual_dependency_digests = sorted(path.name for path in dependency_root.iterdir()) if dependency_root.is_dir() else []
    if actual_dependency_digests != sorted(expected_dependency_digests):
        raise VerificationError("bundled dependency directories differ from the normalized lock")
    ir = (root / "program.onxir").read_bytes()
    if len(ir) > 64 << 20:
        raise VerificationError("IR exceeds bundle size limit")
    verify_ir(ir, profile, resources)
    expected_ir_id = hashlib.sha256(compiler_v1.IR_ID_DOMAIN + ir).hexdigest()
    if (root / "ir-id.txt").read_bytes() != (expected_ir_id + "\n").encode("ascii") or provenance.get("ir_id") != expected_ir_id:
        raise VerificationError("IR identifier mismatch")
    if hashlib.sha256(manifest_bytes).hexdigest() == "":  # keep manifest bytes covered by strict parsing
        raise VerificationError("unreachable manifest digest state")
    with tempfile.TemporaryDirectory(prefix="onyx-compiler-verify-") as temporary:
        rebuilt = pathlib.Path(temporary) / "rebuilt"
        dependency_store = root / "dependencies"
        compiler_v1.write_bundle(compiler_v1.load_package(root / "source",
            dependency_store if dependency_store.exists() else None), rebuilt)
        compare_directories(root, rebuilt)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=pathlib.Path)
    args = parser.parse_args()
    try:
        verify_bundle(args.bundle)
    except (VerificationError, compiler_v1.CompileError) as error:
        print(f"verification failed: {error}")
        return 2
    print("Onyx compiler frontend bundle verified and reproduced")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
