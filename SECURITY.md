# Security policy

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on the **Security** tab of
this repository ("Report a vulnerability"). Please include reproduction
steps, the affected component (crate names are fine), and what an attacker
or prober would observe. Do **not** open public issues for exploitable
behavior.

We aim to respond within 72 hours. Credit is given by default; anonymity
on request.

## Threat model (summary)

The adversary is an on-path censor: passive DPI (keyword/Host filtering,
statistical flow classification), active probing (scans, path guesses,
replayed handshakes), and casual human review of the box. The reasoning
and the design answers live in `docs/adr/`.

Out of scope: endpoint compromise of the client or server host, global
passive traffic correlation, and an adversary willing to block the
server's IP outright — nothing at the protocol layer survives that; see
"Honest limits" in the README for the operational side.

## Operational warnings

- Never set `CRYPTN_ALLOW_PRIVATE=1` on a deployment. It disables the
  SSRF egress guard and exists only for local development against
  loopback test targets.
- The state file (default `/var/lib/cryptn/state.json`) holds the OPAQUE
  server setup, the capability-path secret, and the client credential
  export. Treat it as the crown jewels: `0600`, root-owned. Losing it
  means re-provisioning the client, not a leak — but anyone who reads it
  owns the box's disguise.
- Low volume is a safety property, not a suggestion. Field data correlates
  blocking with per-IP traffic; see the README.
