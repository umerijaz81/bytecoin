# Bytecoin — Jade and Onyx hardening branch

This repository contains the Bytecoin node, wallet, miner, the Jade consensus transition, and the
Onyx Halo2/Pasta privacy backend. Mainnet activation remains deliberately unreachable until every
gate in `release/activation-gates.json` has independently passed.

The authoritative engineering and release documents are:

- `ONYX_IMPLEMENTATION_STATUS.md` — phase-by-phase implementation status and remaining exit criteria;
- `ONYX_PROTOCOL_SPEC.md` and `ONYX_ARCHITECTURE.md` — consensus and architecture definitions;
- `SECURITY_PRIVACY_AUDIT.md` — security/privacy findings and implemented mitigations;
- `docs/Release-Readiness.md` — reproducibility boundary and release ceremony;
- `release/dependencies.lock.json` — exact release dependency identities.

## Supported build boundary

The project requires CMake 3.15+, a C++14 compiler, Python 3, and—when `ONYX_ZK=ON`—the Rust
toolchain pinned by `vendor/onyx-zk/rust-toolchain.toml`. Release inputs currently pin Boost 1.91.0,
OpenSSL 3.5.7, the Bytecoin LMDB revision, RandomX 2.0.1, and the complete vendored Onyx Cargo tree.

Package-manager dependencies are acceptable for local development, but they do not prove release
reproducibility. Release builders must use the exact versions and hashes in
`release/dependencies.lock.json` and follow `docs/Release-Readiness.md`.

Before building, place the pinned LMDB source beside this repository as `../lmdb`, or configure the
equivalent source location expected by CMake. Install Boost and OpenSSL through a trusted package
manager for development, or unpack the locked archives into the parent workspace. Never use the
obsolete Boost 1.69/Bintray or OpenSSL 1.1.1b instructions from historical Bytecoin releases.

## Configure and build

Linux/macOS:

```sh
cmake -S . -B build -DONYX_ZK=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

Windows from a current Visual Studio x64 developer shell:

```powershell
cmake -S . -B build -DONYX_ZK=ON
cmake --build build --config Release --parallel
```

The primary artifacts are written under `bin/`: `bytecoind`, `walletd`, and `minerd`.

`BYTECOIN_HARDWARE_EMULATOR` is `OFF` by default and must remain off for every distributable build.
Enabling it creates a secret-bearing test artifact that is explicitly ineligible for release.

For deterministic qualification, set a numeric `SOURCE_DATE_EPOCH` and enable
`REPRODUCIBLE_BUILD=ON`. The three-platform reference commands and byte-comparison process live in
`.github/workflows/reproducible-binaries.yml`.

## Verify

Run the dependency and activation guards before any release-oriented build:

```sh
python tools/release/verify_dependencies.py
python tools/release/verify_release_gates.py
```

The networked release ceremony must additionally re-fetch and hash immutable upstream inputs:

```sh
python tools/release/verify_dependencies.py --verify-upstream
```

Build the `tests` target and run the relevant suites from the build directory:

```sh
../bin/tests --jade
../bin/tests --zk
../bin/tests --wallet
../bin/tests --wallet-state
```

Additional real-process, compiler, SDK, fuzz, RandomX, release, and reproducibility gates are defined
under `tests/` and `.github/workflows/`. A green local build is not an audit, public testnet soak,
independent binary reproduction, incident drill, or governance approval.

## Platform notes

- Production targets are Linux x86-64, macOS ARM64, and Windows x64.
- SQLite may be selected with `-DUSE_SQLITE=1`; LMDB remains the normal 64-bit daemon backend.
- Big-endian systems are unsupported because inherited serialization and hashing paths still contain
  endian-dependent code.
- iOS, Android, and other embedded targets are experimental and outside the release qualification
  matrix.

See the pinned CI workflows for the current platform packages and compiler invocation. Do not infer
release support from a successful unqualified package-manager build.
