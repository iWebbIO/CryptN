# CONTEXT

Glossary of CryptN's domain language. Implementation details live in ADRs,
not here.

## The disguise

- **Front** — the entire outward-facing surface of the server: what any
  network client sees on port 80.
- **Persona** — the specific innocent identity the front performs. Current:
  *Apache 2.4.58 on Ubuntu, fresh install, forgotten*. One persona per
  deployment; the persona decides every byte not decided by the tunnel.
- **Stock** — behavior copied verbatim from the real software's output
  (files, headers, error pages, limits). "Stock" is a claim of byte-exact
  provenance, not "similar to".

## The seam

- **Capability path** — the single hidden URL prefix (`/<128-bit secret>/`)
  under which the tunnel API lives. Wrong or missing secret behaves exactly
  like the persona (stock 404/405). Unfindable by scanning.
- **Credential** — the operator's secret (256-bit, generated at deploy).
  Presented to OPAQUE at login; never crosses the wire recoverably.
- **Login** — the two-step OPAQUE exchange that ends in a **Session**.

## The tunnel

- **Session** — one logged-in client: bearer token + directional record
  keys derived from the PAKE output.
- **Conversation** — one proxied TCP stream, from SOCKS accept to close.
  Identified by a random 16-byte id, carried (base64) in URLs and JSON.
- **Message** — one upstream POST body or one downstream long-poll item:
  the envelope JSON around one AEAD-encrypted record. The wire word is
  always "message"; the tunnel word is "record".
- **Record** — one XChaCha20-Poly1305 encryption of a padded frame, bound
  to its conversation id and counter via associated data.
- **Frame** — the plaintext event inside a record: Open, Push, Close, or
  Ack (cover traffic).
- **Up / Down** — client→server and server→client directions. Distinct
  record keys per direction.

## Shaping

- **Bucket** — a target plaintext size drawn from a chat-message length
  distribution, so ciphertext lengths never echo tunnel block sizes.
- **First-record padding** — extra headroom on a conversation's first
  records (first-reads shaping).
- **Cover traffic** — Ack frames / presence-shaped chatter at natural
  intervals.

## Adversaries

- **Scanner** — mass internet prober; meets only stock persona behavior.
- **Prober** — targeted tester of a suspected endpoint, including
  replays; gets stock 404s (wrong path) or the app's generic errors
  (right path, no/bad credential).
- **Analyst** — a human reading captures or visiting the box; sees a
  boring forgotten webserver and, if persistent, opaque ciphertext in
  chat-app JSON.

## Failure vocabulary

The API answers everything in a real app's words: `401 invalid email or
password`, `401 session expired`, `409 duplicate message`, `400 invalid
message`, `404 conversation not found`. There is no protocol-shaped error
anywhere on the wire.
