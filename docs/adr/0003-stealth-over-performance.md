# ADR 0003 — Stealth over performance, everywhere

## Status

Accepted. This is the project's constitution; every other ADR is
subordinate to it.

## Context

Censorship-evasion projects routinely trade a little camouflage for a lot
of throughput (multiplexing, large frames, long-lived connections, minimal
padding). Field data says the opposite trade is correct for this
environment: connection lifetime × protocol mismatch is the strongest
real-world tell (surviving Iranian deployments bound connections to
minutes and gigabytes), and record-length statistics are a realistic
classifier (the record-shaping arms race in the TLS world).

## Decision

Whenever stealth and performance conflict, stealth wins, without
re-litigation:

- **Bounded connection lifetimes**: client HTTP connections live 30–120s
  (jittered); long-polls cap at 25s; no hours-long flows.
- **Size shaping**: records padded to chat-message buckets before
  encryption; first records extra-padded; bulk payloads would use the
  attachments lane with plausible caps and scan latency.
- **Per-install variance**: install-seeded jitters and cadences so two
  deployments never produce identical timing fingerprints.
- **No multiplexing tricks**: one conversation = one logical stream; its
  messages ride plain request/response cycles like a real app.

## Consequences

- Throughput and latency are deliberately mediocre; bulk transfers are
  painful. Accepted.
- The design point is a handful of users browsing; not a community VPN.
- Every future optimization must prove it does not change the traffic
  shape before it is considered.
