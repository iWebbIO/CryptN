# ADR 0006 — Hand-rolled HTTP/1.1 for byte-exactness

## Status

Accepted.

## Context

Every off-the-shelf HTTP stack normalizes something: header casing,
ordering, whitespace, default headers, error pages, tolerance for
malformed input. For an ordinary service this is virtue; for a server
whose *entire purpose* is to be byte-identical to stock Apache, each
normalization is a fingerprint mismatch. Framework defaults are also
invisible decisions — the worst kind when the design goal is total
control of the wire.

## Decision

Both the server and client sides of the tunnel path use `cryptn-front`,
a hand-rolled HTTP/1.1 engine with explicit, Apache-shaped strictness:

- Parser: request-line limits (8190 → 414), field limits (100 fields,
  8190/field → 400), one-Host rule for 1.1, obs-fold rejection, strict
  %-decoding (bad escape → 400), dot-segment resolution preserving `//`,
  TE+CL smuggling rejection, non-chunked transfer-coding → 501,
  malformed → 400, mid-request stall → 408, idle keep-alive → silent
  close. HTTP/0.9 answered bare-body.
- Emitter: an ordered header vector serialized exactly as built — no
  defaults, no reordering, no casing normalization. Status-line reasons
  are the httpd 2.4 set.
- Server loop: keep-alive semantics per version (1.1 default on,
  1.0 opt-in, 0.9 none), `MaxKeepAliveRequests` bound, `Expect:
  100-continue` interim response before body read.
- Client: same verbatim emission discipline, with a jittered 30–120s
  connection lifetime budget (ADR 0003).

## Consequences

- The persona's byte claims are enforceable in tests (golden responses),
  because emission is deterministic and owned.
- The parser is a maintained surface; it is covered by the strictness
  matrix in `cryptn-front`'s integration suite.
- No `hyper`/`axum` in the tunnel path — they remain available for
  tooling, but the wire code is all ours.
