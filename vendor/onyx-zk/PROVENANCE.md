# onyx-zk dependency provenance

The Onyx ZK backend is **wrappers only** — all cryptography comes from the pinned upstream crates
below. Versions are locked in `Cargo.lock`. Before mainnet use these are `cargo vendor`'d and built
offline (see `README.md`), and the protocol + circuits are externally audited.

Resolved with Rust 1.94.1.

| Crate | Version | crates.io sha256 (from Cargo.lock) |
|-------|---------|------------------------------------|
| halo2_proofs | 0.3.2 | 05713f117155643ce10975e0bee44a274bcda2f4bb5ef29a999ad67c1fa8d4d3 |
| halo2_gadgets | 0.5.0 | fb2a697cad929f706b7987fe804ad57d43622cd37463ba7e4d662a926fdcfea3 |
| pasta_curves | 0.5.1 | d3e57598f73cc7e1b2ac63c79c517b31a0877cd7c402cdcaa311b5208de7a095 |
| ff | 0.13.1 | c0b50bfb653653f9ca9095b427bed08ab8d75a137839d9ad64eb11810d5b6393 |
| group | 0.13.0 | f0f9ef7462f7c099f518d754361858f86d8a07af53ba9af0fe635bbccb151a63 |
| rand | 0.8.6 | 5ca0ecfa931c29007047d1bc58e623ab12e5590e8c7cc53200d5202b69266d8a |

Note: `halo2_proofs`/`halo2_gadgets` 0.3.x of `halo2_gadgets` are yanked on crates.io; `halo2_gadgets`
0.5.0 is the current published line and resolves against `halo2_proofs` 0.3.2 (the single-backend IPA
API over Pasta). Upgrades are explicit, reviewed changes — never floating.

The full transitive graph is captured in `Cargo.lock` (committed). Regenerate the audit list with:
```
cargo tree --no-default-features --edges normal
```
