# Onyx and protocol fuzzing

Configure with Clang/libFuzzer and sanitizers:

```text
cmake -S . -B build-fuzz -DSANITIZE=fuzzer,address,undefined -DONYX_ZK=ON
cmake --build build-fuzz --target fuzzer
build-fuzz/fuzzer corpus/ -artifact_prefix=artifacts/
```

Each input starts with a one-byte selector followed by the bytes passed to the target parser. Restored
selectors `0..15` cover Levin handshake, sync, relay, stem-relay and object messages; `128..137` cover consensus
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

Keep crash artifacts and minimized regression inputs. Every confirmed issue must gain a deterministic
unit/regression test before the fix is accepted.
