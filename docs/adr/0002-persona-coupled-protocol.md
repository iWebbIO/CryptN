# ADR 0002 — Persona-coupled protocol

## Status

Accepted.

## Context

An anti-DPI tunnel has two camouflage problems: the server's *idle*
appearance (what scanners see) and its *active* appearance (what the
traffic looks like while in use). Most designs solve them separately —
a decoy website plus a protocol with its own error vocabulary — and the
seam shows: probe a path, get an error no real site would give; watch the
traffic, see shapes no real site produces.

## Decision

One persona answers everything, and the tunnel *is* an application inside
that persona. Concretely: the box performs a stock Apache2-Ubuntu install;
the tunnel is a never-launched E2E chat app's API parked at a secret path
behind it. Every tunnel behavior has a native story in the persona —
ciphertext is *expected* in an E2E messenger's bodies, long-poll GETs are
how chat apps fetch, presence/ack frames are typing indicators, and every
error is the app's own vocabulary (`401 invalid email or password`,
`409 duplicate message`). There is no bolted-on decoy and no
protocol-shaped error anywhere.

## Consequences

- Probe-resistance falls out of the single code path: invalid traffic at
  the capability path gets the persona's stock 404 — the path "does not
  exist" — and a right path with bad credentials gets the app's login
  error, which is what a real app gives.
- The persona's constraints bind the protocol: only GET/POST/DELETE,
  request/response semantics, JSON bodies, chat-plausible sizes.
- The wire vocabulary is fixed by the envelope layer; adding any visible
  field requires justifying its chat-app story first.
