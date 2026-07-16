# Onyx compiler frontend qualification

The tests build the same package below two different absolute paths, compare every emitted byte and
run the strict bundle decoder/recompiler. Negative cases mutate the IR, use noncanonical JSON/UTF-8
source framing, exceed loop/resource bounds and introduce unsupported language constructs.

This suite qualifies only the non-registrable frontend artifact boundary. It does not claim Halo2
lowering, verifying-key regeneration, proof generation, compiler audit or production activation.
