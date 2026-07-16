"""Deterministic, standard-library-only PEP 517 backend for the Onyx SDK wheel."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import pathlib
import zipfile


NAME = "bytecoin-onyx-sdk"
VERSION = "1.1.0"
DIST_NAME = "bytecoin_onyx_sdk"
DIST_INFO = f"{DIST_NAME}-{VERSION}.dist-info"
WHEEL_NAME = f"{DIST_NAME}-{VERSION}-py3-none-any.whl"
ROOT = pathlib.Path(__file__).resolve().parent
PACKAGE_FILES = (
    "onyx_sdk.py",
    "bytecoin_onyx/__init__.py",
    "bytecoin_onyx/rpc.py",
    "bytecoin_onyx/standard_programs.py",
    "bytecoin_onyx/wallet_rpc_v1.json",
)
METADATA = f"""Metadata-Version: 2.1
Name: {NAME}
Version: {VERSION}
Summary: Versioned offline bindings and wallet RPC codecs for Bytecoin Onyx ABI profile v1
License: LGPL-3.0-or-later
Requires-Python: >=3.9
"""
WHEEL = """Wheel-Version: 1.0
Generator: bytecoin-onyx-sdk deterministic backend
Root-Is-Purelib: true
Tag: py3-none-any
"""


def _write_text(path: pathlib.Path, value: str) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as output:
        output.write(value)


def _metadata_directory(parent: pathlib.Path) -> pathlib.Path:
    result = parent / DIST_INFO
    result.mkdir(parents=True, exist_ok=True)
    _write_text(result / "METADATA", METADATA)
    _write_text(result / "WHEEL", WHEEL)
    return result


def get_requires_for_build_wheel(config_settings=None):
    return []


def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    _metadata_directory(pathlib.Path(metadata_directory))
    return DIST_INFO


def _record_entry(name: str, data: bytes) -> tuple[str, str, str]:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
    return name, f"sha256={digest}", str(len(data))


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    return info


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    output = pathlib.Path(wheel_directory)
    output.mkdir(parents=True, exist_ok=True)
    files = {name: (ROOT / name).read_bytes() for name in PACKAGE_FILES}
    files[f"{DIST_INFO}/METADATA"] = METADATA.encode("utf-8")
    files[f"{DIST_INFO}/WHEEL"] = WHEEL.encode("utf-8")

    record_rows = [_record_entry(name, data) for name, data in sorted(files.items())]
    record_name = f"{DIST_INFO}/RECORD"
    record_rows.append((record_name, "", ""))
    record_stream = io.StringIO(newline="")
    csv.writer(record_stream, lineterminator="\n").writerows(record_rows)
    files[record_name] = record_stream.getvalue().encode("utf-8")

    wheel_path = output / WHEEL_NAME
    with zipfile.ZipFile(wheel_path, "w") as archive:
        for name, data in sorted(files.items()):
            archive.writestr(_zip_info(name), data)
    return WHEEL_NAME
