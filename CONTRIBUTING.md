# Contributing to CryptN

Thanks for helping. CryptN is a small, deliberately narrow project — read
this first so changes land quickly and safely.

## The four laws

These are ADR-level decisions (see `docs/adr/`); changing any of them needs
a new ADR, not just a diff:

1. **The persona is the protocol.** Every byte a stranger can observe must
   be a byte a stock Apache2-on-Ubuntu box — or the parked chat app behind
   the capability path — could have emitted. If a change adds a visible
   signature (a header, a length, a timing pattern), it is a bug, not a
   feature.
2. **No TLS, no websockets, no HTTP/2, no UDP on the tunnel path.** The
   design bet is that plain HTTP/1.1 is the shape that survives; protocol
   "upgrades" are how tunnels die.
3. **Stealth beats performance.** Padding, long-polls, extra round trips,
   tiny volumes: intentional. Patches that make the wire faster by
   shrinking the disguise are rejections, not optimizations.
4. **Tiny dependency tree.** Anything new in `Cargo.toml` needs a
   justification in the PR — supply-chain surface is attack surface.
   Crypto comes from the RustCrypto family only; no hand-rolled
   primitives.

## Ground rules

- `CONTEXT.md` is the shared glossary; use its vocabulary in code, tests,
  and PR descriptions.
- New behavior comes with tests. Everything below must stay green:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test -p cryptn-server --features dev --test e2e
tests/parity/smoke.sh   # live binary smoke: needs a release build, python3, curl
```

- The byte-parity assertions in `crates/cryptn-persona` tests are
  executable spec. If the persona changes a byte, the goldens change in the
  same commit, with provenance: which httpd/apache2 version, which
  packaging file the new bytes came from.
- The egress guard is a security boundary (`crates/cryptn-egress`): the
  production profile rejects loopback, private, CGNAT, link-local, and
  reserved ranges. Changes there need tests showing every class of
  blocked address stays blocked.

## Security issues

Do not open a public issue for anything exploitable — see `SECURITY.md`
for private reporting.

## Pull requests

Small, focused diffs. In the description, answer the observer question:
*what would a stranger newly see on the wire because of this change?*
("Nothing new" is the right answer surprisingly often.) If a PR changes
design, write or amend the ADR first and link it.
