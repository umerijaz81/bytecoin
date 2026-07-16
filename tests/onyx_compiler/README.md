# Onyx compiler frontend qualification

The tests build the same package below two different absolute paths, compare every emitted byte and
run the strict bundle decoder/recompiler. Negative cases mutate the IR, use noncanonical JSON/UTF-8
source framing, exceed loop/resource bounds and introduce unsupported language constructs. A seeded
grammar-directed campaign also compares valid scalar programs with an independent arithmetic oracle,
checks canonical mutation rejection and lowers a bounded prefix through the real Halo2 backend.

The supported compiler subset has real Halo2 lowering, per-export verifying-key regeneration and proof
vectors, but it remains non-registrable. These regression tests do not claim a sustained fuzz campaign,
independent compiler audit, testnet qualification or production activation.
