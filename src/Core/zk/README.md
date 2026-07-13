# src/Core/zk — Onyx (V6) zero-knowledge seam

This directory anchors the zero-knowledge core of the Onyx programmable-privacy protocol. See
`ONYX_ARCHITECTURE.md` at the repo root for the full design.

**Current contents are a design stub, not an implementation.**

- `IProofSystem.hpp` — the abstract proof backend. Fixes the interface between block validation /
  the mempool and the (vendored) proving system, and the place a future post-quantum (STARK)
  backend slots in. **Not yet added to `CMakeLists.txt`** so it cannot affect the build.

What lands here in the phased rollout (each vendored + audited, testnet-first):

- **O0** — a vendored Halo2/PLONKish backend implementing `IProofSystem` (over the Pasta curve
  cycle), plus Poseidon/Sinsemilla gadgets and Pedersen value commitments.
- **O1** — the note-commitment incremental Merkle tree, the nullifier set, and the note
  format + in-band encryption (reusing `src/crypto/chacha.*`).
- **O2** — the spend/viewing-key hierarchy.
- **O4** — the program / verifying-key registry and the standard circuit library.

Non-negotiable: nothing consensus-critical is hand-rolled. Implementations are peer-reviewed,
vendored, and externally audited before any mainnet activation height is committed.
