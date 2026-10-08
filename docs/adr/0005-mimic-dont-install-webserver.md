# ADR 0005 — Mimic the webserver, never install it

## Status

Accepted.

## Context

Earlier design iterations considered installing a real Apache2 (or
LiteSpeed) on the VPS and hiding behind a proxy directive. That gives a
perfect fingerprint for free — but it violates deployment discipline:
package state, an admin surface, version drift, another process to
harden, and a hidden proxy directive that itself becomes a signature if
the box is ever inspected. The operator should ship one binary and
nothing else.

## Decision

The server binary *binds port 80 itself and performs the webserver*.
No webserver package is ever installed. Byte-fidelity is achieved by
sourcing every literal from the real thing at build time:

- The default page is the Ubuntu apache2 packaging's actual
  `index.html` (2022-03-22 revision), embedded byte-exact, along with the
  real `ubuntu-logo.png`.
- Error-page text, title/h1 shape, DOCTYPE, and the
  `Apache/2.4.58 (Ubuntu) Server at <host> Port 80` footer are quoted
  verbatim from httpd 2.4.58's `http_protocol.c` / `core.c`.
- Limits and semantics follow httpd's documented defaults
  (`LimitRequestLine` 8190, `LimitRequestFields` 100, `Timeout` 300,
  `KeepAliveTimeout` 5, `MaxKeepAliveRequests` 100).

## Consequences

- The disguise cannot be undermined by package updates or config drift on
  the box — there is nothing to drift.
- Fidelity must track the reference: when Ubuntu ships a new apache2,
  the persona's version string and goldens move with it (a stale version
  is itself a mild long-term tell). The `cryptn-persona` crate owns this.
- The reference corpus (parity tests) documents provenance for every
  literal, so "byte-exact" is an auditable claim, not a hope.
