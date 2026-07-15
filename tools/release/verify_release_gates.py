#!/usr/bin/env python3
"""Prevent activation-height changes while mandatory release evidence is incomplete."""

from __future__ import annotations

import json
import re
import sys

from release_common import ROOT


REQUIRED_GATES = {
    "source-provenance",
    "independent-audits",
    "public-testnet-soak",
    "reproducible-platform-binaries",
    "incident-response-drill",
    "governance-approval",
}
ALLOWED_STATUS = {"pending", "implemented", "passed"}


def verify(gates_document: dict, config: str) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    if gates_document.get("schema_version") != 1:
        errors.append("activation gate schema_version must be 1")
    gates = gates_document.get("gates", [])
    by_id = {gate.get("id"): gate for gate in gates if isinstance(gate, dict)}
    if len(by_id) != len(gates):
        errors.append("activation gate identifiers must be present and unique")
    if missing := REQUIRED_GATES - by_id.keys():
        errors.append(f"missing activation gates: {sorted(missing)}")
    for gate_id, gate in by_id.items():
        status = gate.get("status")
        evidence = gate.get("evidence")
        if status not in ALLOWED_STATUS:
            errors.append(f"{gate_id}: invalid status {status}")
        if not isinstance(evidence, list):
            errors.append(f"{gate_id}: evidence must be an array")
            continue
        for relative in evidence:
            if not isinstance(relative, str) or not relative or not (ROOT / relative).exists():
                errors.append(f"{gate_id}: missing repository evidence {relative!r}")
        if status == "passed" and not evidence:
            errors.append(f"{gate_id}: passed status requires concrete evidence")
    audit_gate = by_id.get("independent-audits", {})
    if audit_gate.get("status") == "passed" and len(audit_gate.get("evidence", [])) < int(
        audit_gate.get("minimum_independent_reports", 2)
    ):
        errors.append("independent-audits: passed status requires two distinct report paths")

    placeholders = gates_document.get("placeholder_heights", {})
    current: dict[str, int] = {}
    for name, expected in placeholders.items():
        match = re.search(rf"\b{name}\s*=\s*(\d+)\s*;", config)
        if not match:
            errors.append(f"activation constant not found: {name}")
            continue
        current[name] = int(match.group(1))
        if not isinstance(expected, int) or expected <= 0:
            errors.append(f"invalid placeholder height for {name}")

    incomplete = [
        gate_id
        for gate_id, gate in by_id.items()
        if gate.get("required_for_activation") and gate.get("status") != "passed"
    ]
    if incomplete:
        for name, expected in placeholders.items():
            if current.get(name) != expected:
                errors.append(
                    f"{name} changed from fail-closed placeholder {expected} while gates remain incomplete: {incomplete}"
                )
    return errors, incomplete


def main() -> int:
    gate_path = ROOT / "release" / "activation-gates.json"
    gates_document = json.loads(gate_path.read_text(encoding="utf-8"))
    config = (ROOT / "src" / "CryptoNoteConfig.hpp").read_text(encoding="utf-8")
    errors, incomplete = verify(gates_document, config)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"release gates verified; incomplete activation gates: {', '.join(incomplete) if incomplete else 'none'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
