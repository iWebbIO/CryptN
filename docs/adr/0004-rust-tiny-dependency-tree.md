# ADR 0004 — Rust, tiny dependency tree

## Status

Accepted.

## Context

The implementation language needed: byte-level control (the whole point
is exact wire output), a serious crypto ecosystem with audited primitives
(no hand-rolled ciphers), static single-binary deployment on a bare VPS,
and a dependency tree small enough to audit by reading.

## Decision

Rust, as a Cargo workspace of small crates. Dependency policy:

- Crypto: RustCrypto only (`chacha20poly1305`, `hkdf`, `sha2`) plus
  `opaque-ke` (OPAQUE) and `voprf` — no other crypto families.
- Async: `tokio` only, for sockets and timers. No framework HTTP server
  or client anywhere in the tunnel path — both sides are hand-rolled in
  `cryptn-front` so every byte is our decision.
- Encoding: `serde`/`serde_json`/`base64`. Misc: `rand`, `subtle`,
  `zeroize`, `thiserror`.
- `Cargo.lock` committed; `cargo audit` in CI.

## Consequences

- Two ~800KB stripped binaries with no runtime to install.
- The hand-rolled HTTP stack is the largest maintenance surface; it is
  also the crate with the strongest test suite (strictness matrix vs
  Apache's documented limits).
- Upgrades are rare and visible (crypto crates move slowly).
