# Onyx and protocol fuzzing

Configure with Clang/libFuzzer and sanitizers:

```text
cmake -S . -B build-fuzz -DSANITIZE=fuzzer,address,undefined -DONYX_ZK=ON
cmake --build build-fuzz --target fuzzer
build-fuzz/artifacts/bin/fuzzer corpus/ -artifact_prefix=artifacts/
```

The project harness is emitted under the owning build tree as
`build-fuzz/artifacts/bin/fuzzer` by the default CMake layout.
`tools/fuzz/generate_seed_corpus.py corpus` creates the same
deterministic starter corpus used by CI.

Each input starts with a one-byte selector followed by the bytes passed to the target parser. Restored
selectors `0..16` cover Levin handshake, sync, relay, stem-relay, SOCKS5 and object messages; `128..137` cover consensus
binary objects including transactions and blocks; `200` covers JSON; and `201` covers addresses.

Onyx-enabled builds additionally expose:

| Selector | Target |
|---|---|
| `202` | Authorized transfer/mixed-token envelope verifier |
| `203` | Legacy-to-Onyx bridge verifier/extractor |
| `204` | Program deployment verifier/extractor |
| `205` | Token issuance verifier/extractor |

The Onyx selectors use production depth 32 and circuit K 20. Random malformed data normally fails
during bounded canonical decoding before proof work. Seed the corpus with valid test envelopes so the
fuzzer can mutate deeper proof, signature, ciphertext and public-input paths. Run sustained campaigns
under ASan/UBSan before any release; a compiling target is not evidence of adequate fuzz coverage.

`.github/workflows/sanitizer-fuzz.yml` builds the complete Onyx-enabled harness with Clang,
ASan, UBSan and libFuzzer. Pull requests and pushes run a bounded 90-second regression campaign;
the weekly schedule runs for 15 minutes and retains crash artifacts. These jobs catch regressions but
do not satisfy the release requirement for sustained, independently reviewed campaigns over the
valid proof-envelope corpus.

The first complete push qualification passed on 2026-07-16 in GitHub Actions run `29513818205`,
including the Onyx-enabled C++ build, corpus tests and bounded campaign.

Keep crash artifacts and minimized regression inputs. Every confirmed issue must gain a deterministic
unit/regression test before the fix is accepted.

## Compiler structured campaign

`tools/onyx/structured_fuzz_v1.py` separately exercises the compiler trust boundary with a seeded,
grammar-directed campaign. It generates bounded valid field, Boolean and checked-integer programs,
computes results with an operator-level oracle independent of the compiler evaluator, requires deterministic
IR reproduction, and sends canonical IR through the independent decoder. Every case also checks that truncated,
trailing-byte and overlong-ULEB mutations fail closed. When `--backend` is supplied, a bounded prefix is lowered
through the real Halo2 backend and must produce an export-bound descriptor v2.

The locked Onyx core workflow runs 48 deterministic cases on every supported platform and lowers eight through
Halo2. This regression campaign complements rather than replaces coverage-guided fuzzing, sanitizers, long-running
campaigns, minimized crash retention, and independent review. Reproduce it locally with:

```text
python tools/onyx/structured_fuzz_v1.py --cases 48 --backend vendor/onyx-zk/target/release/onyx-compiler-backend
```

## Shielded-state snapshot structured campaign

`tools/onyx/snapshot_corruption_campaign.py` runs four published seeds through the Rust snapshot
decoder using canonical empty/anchor/nullifier/program-state fixtures. Six targeted structural errors
must produce their exact decoder classes; seeded bit, overwrite, truncate, append, delete, insert,
range-fill, and segment-copy mutations must reject or canonicalize byte-for-byte. The weekly retained
configuration runs 20,000 cases per seed with CPU/RSS/output/time ceilings.

This campaign is deterministic regression evidence and gives exact replay identities. It complements
the sanitizer/libFuzzer harness above; it does not provide edge coverage. A separate deterministic
process campaigns mutate small SQLite/rollback-journal images and deterministic WAL/checkpoint file
bundles. A separate bounded runner forces `SQLITE_FULL` during state and undo writes. These do not
fuzz a live checkpoint routine or replace sustained coverage-guided campaigns. A compile-time-only
forwarding VFS injects repeated independent journal/database/WAL write/sync errors plus first-byte,
half-write, and final-byte-short prefixes on all three file classes. The v3 campaign runs 45 faults
across fresh images plus a committed control and records both requested and persisted byte counts.
Combined faults, exhaustive or fuzz-selected cut positions, and directory-sync errors remain.
