# ADR 0001 — Plain HTTP outside, mandatory AEAD inside

## Status

Accepted.

## Context

The deployment environment (Iranian national DPI, 2024–2026) kills
TLS-based proxy families via SNI/RST injection, per-connection TLS-in-TLS
classification, and response-direction interference. After the June 2025
blackouts, plain-HTTP tunnels were the surviving category on some ISPs,
because plain HTTP is filtered selectively (keyword/Host in the first
data packet) rather than blocked wholesale. Any design that puts a TLS
layer on the tunnel path re-enters the killed category. But plain HTTP
means the censor reads every byte — including any target hostname or
blocked keyword in a body.

## Decision

1. The tunnel transport is HTTP/1.1 plaintext, port 80, forever. No TLS,
   no WebSocket, no HTTP/2 upgrade, no CONNECT method.
2. Every tunneled byte — target hostnames included — is AEAD ciphertext
   (XChaCha20-Poly1305) before it becomes a JSON field. There is no
   "cleartext mode".
3. Login is a PAKE (OPAQUE, RFC 9380), so nothing password-derived crosses
   the wire even during authentication.

## Consequences

- Structurally immune to SNI/JA3/TLS-in-TLS fingerprinting: there is no
  TLS handshake to fingerprint.
- The visible JSON must forever look like an innocent app's API; that is
  a content discipline owned by the envelope layer (which generates every
  visible value).
- The first data packet is honest ASCII (`POST /path HTTP/1.1`), below the
  entropy heuristics documented against fully-encrypted protocols.
- Performance is sacrificed: every request/response cycle is a "chat
  message" with padding — the explicit design priority.
