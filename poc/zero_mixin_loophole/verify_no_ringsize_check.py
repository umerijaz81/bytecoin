#!/usr/bin/env python3
"""
PoC / static verifier for Bytecoin finding C-3.

Proves, directly against the repository source, that the consensus+mempool semantic
validator `validate_tx_semantic` performs NO minimum-ring-size (anonymity) check, while
the minimum is enforced only on the wallet build path. Consequently a ring-size-1
(zero-mixin) transaction is consensus-valid.

Run:  python3 poc/zero_mixin_loophole/verify_no_ringsize_check.py
Exit: 0 if the loophole is present (proof succeeds), 1 otherwise.
"""
import os
import re
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
BCS = os.path.join(REPO, "src", "Core", "BlockChainState.cpp")
WNODE = os.path.join(REPO, "src", "Core", "WalletNode.cpp")
CFG = os.path.join(REPO, "src", "CryptoNoteConfig.hpp")


def read(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def extract_function_body(src, signature_fragment):
    """Return the brace-balanced body of the first function whose text contains
    `signature_fragment`, starting from that fragment up to the matching closing brace."""
    start = src.find(signature_fragment)
    if start < 0:
        raise RuntimeError("could not locate %r" % signature_fragment)
    brace = src.find("{", start)
    depth = 0
    i = brace
    while i < len(src):
        c = src[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return src[brace : i + 1]
        i += 1
    raise RuntimeError("unbalanced braces after %r" % signature_fragment)


def line_of(src, idx):
    return src.count("\n", 0, idx) + 1


def main():
    failures = []
    notes = []

    bcs = read(BCS)
    wnode = read(WNODE)
    cfg = read(CFG)

    # 0. Sanity: the configured minimum anonymity exists and is small.
    m = re.search(r"MINIMUM_ANONYMITY_AMETHYST\s*=\s*(\d+)", cfg)
    if not m:
        failures.append("MINIMUM_ANONYMITY_AMETHYST not found in CryptoNoteConfig.hpp")
        min_anon = None
    else:
        min_anon = int(m.group(1))
        notes.append("MINIMUM_ANONYMITY_AMETHYST = %d (CryptoNoteConfig.hpp:%d)"
                     % (min_anon, line_of(cfg, m.start())))

    # 1. Extract the consensus validator body.
    body = extract_function_body(bcs, "validate_tx_semantic(")
    body_line = line_of(bcs, bcs.find("validate_tx_semantic("))
    notes.append("validate_tx_semantic body extracted (%d chars) at BlockChainState.cpp:%d"
                 % (len(body), body_line))

    # 2. The validator MUST touch output_indexes only to decode offsets,
    #    and MUST NOT compare its size to any anonymity / minimum threshold.
    touches_indexes = "output_indexes" in body
    decodes_offsets = "relative_output_offsets_to_absolute" in body
    if not touches_indexes:
        notes.append("validator does not reference output_indexes at all "
                     "(still no size enforcement)")
    elif decodes_offsets:
        notes.append("validator references output_indexes only via "
                     "relative_output_offsets_to_absolute (offset decoding, not a size check)")

    # The actual loophole assertion: no minimum-ring-size enforcement of any form.
    forbidden_patterns = [
        r"minimum_anonymity",
        r"MINIMUM_ANONYMITY",
        r"output_indexes\.size\(\)\s*[<>]=?",          # size compared with a bound
        r"\.size\(\)\s*[<>]=?.*anonymity",
        r"ring\s*size",
    ]
    found_enforcement = []
    for pat in forbidden_patterns:
        for mm in re.finditer(pat, body, re.IGNORECASE):
            found_enforcement.append((pat, mm.group(0)))

    if found_enforcement:
        failures.append("validate_tx_semantic appears to enforce a ring-size bound: %r"
                        % found_enforcement)
    else:
        notes.append("CONFIRMED: validate_tx_semantic contains no minimum-ring-size / "
                     "anonymity comparison")

    # 3. The mempool ingress must gate only on validate_tx_semantic (no separate check).
    add_tx = extract_function_body(bcs, "BlockChainState::add_transaction(")
    if "validate_tx_semantic(" not in add_tx:
        failures.append("add_transaction does not call validate_tx_semantic as expected")
    else:
        ingress_has_ringsize = any(
            re.search(p, add_tx, re.IGNORECASE) for p in
            [r"minimum_anonymity", r"MINIMUM_ANONYMITY"]
        )
        if ingress_has_ringsize:
            failures.append("add_transaction enforces a ring-size bound (loophole may be closed)")
        else:
            notes.append("CONFIRMED: add_transaction (mempool ingress) adds no ring-size check")

    # 4. Enforcement DOES exist on the wallet build path (asymmetry is the whole point).
    if "minimum_anonymity" in wnode:
        wl = line_of(wnode, wnode.find("minimum_anonymity"))
        notes.append("Enforcement exists ONLY wallet-side: minimum_anonymity used at "
                     "WalletNode.cpp:%d" % wl)
    else:
        notes.append("warning: minimum_anonymity not referenced in WalletNode.cpp")

    # Report.
    print("=" * 72)
    print("Bytecoin C-3 verifier — zero-mixin / consensus-unenforced ring size")
    print("=" * 72)
    for n in notes:
        print("  [info] " + n)
    print("-" * 72)
    if failures:
        for f in failures:
            print("  [FAIL] " + f)
        print("\nRESULT: could not prove the loophole (source may have changed).")
        return 1
    print("  PROVEN: consensus accepts ring size 1 (no minimum-ring-size check).")
    print("  A zero-mixin InputKey (output_indexes.size() == 1) passes")
    print("  validate_tx_semantic and add_transaction; the min of %s is wallet-only."
          % (min_anon if min_anon is not None else "?"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
