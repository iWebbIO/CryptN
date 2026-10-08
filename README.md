# CryptN

[![CI](https://github.com/iWebbIO/CryptN/actions/workflows/ci.yml/badge.svg)](https://github.com/iWebbIO/CryptN/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT_OR_Apache--2.0-blue)](#license)

A censorship-resistance core whose server **is** a stock Apache2-on-Ubuntu
webserver — because it is not one, but a hand-rolled Rust binary that
reproduces one byte-for-byte.

To any scanner, crawler, prober, or human: a forgotten Ubuntu VPS serving
the default page. To the operator's client, which knows a 128-bit
capability path and a PAKE credential: a SOCKS5 proxy whose traffic is
indistinguishable from a small web app's JSON API over plain HTTP.

Built for the Iranian DPI environment, where after the 2025 blackouts
plain-HTTP tunnels survived on some ISPs while TLS-based VPNs (VLESS,
VMess, Trojan) were killed by SNI/RST and TLS-in-TLS classification —
because plain HTTP is filtered by keyword/Host allowlists, not blocked
wholesale. CryptN's bet: carry ciphertext inside boring, well-formed
chat-app JSON over port 80, behind a front that is byte-identical to the
most common server configuration on the internet.

**Not for hostile networks' casual use.** Single operator, small trusted
circle, low volume. See [Honest limits](#honest-limits).

## What it looks like on the wire

```
$ curl -i http://your-box/
HTTP/1.1 200 OK
Date: ...
Server: Apache/2.4.58 (Ubuntu)
Last-Modified: ...
ETag: "29cd-29b0-6603ac8f"
Accept-Ranges: bytes
Content-Length: 10672
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" ...>
... the real "Apache2 Ubuntu Default Page: It works" page ...

$ curl -i http://your-box/wp-admin/setup-config.php
HTTP/1.1 404 Not Found
...
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.58 (Ubuntu) Server at your-box Port 80</address>
```

Every stock behavior is reproduced: default page (the actual Ubuntu
packaging file, byte-exact, with the real logo), stock error pages quoted
verbatim from httpd 2.4.58 sources, header order and casing, ETag /
conditional GET (304) / Range (206/416), TRACE echo, `OPTIONS` with the
stock `Allow` list, 405/501 method semantics, `/icons/` alias, `/server-status`
404, request-smuggling rejections, `LimitRequestLine` 8190 with 414s,
408 timeouts, HTTP/0.9 legacy handling — and the 128-bit capability path
answers all of that too when the credential is wrong (stock 404).

The tunnel itself rides the persona app's API:

- `POST /<secret>/api/v1/session` — OPAQUE (RFC 9380) two-step login;
  the credential never crosses the wire in any recoverable form
- `POST /<secret>/api/v1/messages` — upstream data, one encrypted record
  per "message" (padded to chat-message size buckets)
- `GET  /<secret>/api/v1/conversations/<id>/messages?timeout=10` —
  downstream long-poll, exactly how chat apps fetch
- `DELETE /<secret>/api/v1/session` — logout

Every payload is XChaCha20-Poly1305 AEAD ciphertext (per-session keys via
HKDF from the PAKE output), so the on-path censor reads only JSON field
names and base64 — never a target hostname. Replays get the app's own
error vocabulary: `401 {"error":"invalid email or password"}` /
`409 {"error":"duplicate message"}` — never anything protocol-shaped.

## Deploy

On an Ubuntu VPS (port 80 reachable, clean IP):

```sh
git clone https://github.com/iWebbIO/CryptN && cd CryptN
cargo build --release

sudo mkdir -p /var/lib/cryptn
sudo CRYPTN_BIND=0.0.0.0:80 \
     CRYPTN_STATE_DIR=/var/lib/cryptn \
     ./target/release/cryptn-server
# → prints the client credential + capability path ONCE; save them.
```

Install as a systemd unit (see `deploy/cryptn-server.service`).

On your machine:

```sh
CRYPTN_SERVER=your-box.example \
CRYPTN_SECRET=<printed secret> \
CRYPTN_CREDENTIAL=<printed credential> \
CRYPTN_SOCKS=127.0.0.1:1080 \
./target/release/cryptn-client
```

Then point anything at `socks5://127.0.0.1:1080` (remote-DNS by default —
target hostnames never touch the local resolver).

### Operational hygiene (this is most of your safety)

- **Low volume.** Field data correlates VPS IP blocking with traffic:
  a ~200-user server's IP died in ~2h; a 5-user one lasted ~2 days.
  Small circle only.
- **Boring domain, WHOIS privacy, no VPN vocabulary** in the domain or
  anything visible; DNS poisoning after detection is documented within
  ~24h — keep a rotation domain ready (regenerate `state.json` = new
  secret + credential, redeploy).
- **No CDN** (CDNs force HTTPS redirects, which breaks the plain-HTTP
  story).
- **Do not set `CRYPTN_ALLOW_PRIVATE=1`** on a real deployment; it only
  exists for local development against loopback test targets.
- 443 is off. A stock forgotten box has no TLS; that is the disguise.

## Layout

```
crates/
  cryptn-front      hand-rolled HTTP/1.1 (byte-exact parse + emit)
  cryptn-persona    the Apache2-Ubuntu persona (assets + semantics)
  cryptn-pake       OPAQUE login (Ristretto255 + TripleDH, opaque-ke)
  cryptn-record     XChaCha20-Poly1305 records + replay defense
  cryptn-session    AEAD bearer tokens
  cryptn-envelope   JSON wire vocabulary + size shaping
  cryptn-tunnel      conversation framing (Open/Push/Close/Ack)
  cryptn-egress     SSRF-guarded dialing (private ranges rejected)
  cryptn-server     the box: persona front + capability dispatch + API
  cryptn-client     SOCKS5 acceptor + browser-shaped HTTP client
  cryptn-parity     reserved for the corpus/parity harness (placeholder)
tests/parity/smoke.sh   live end-to-end smoke (curl through the proxy)
docs/adr/          the six design decisions, written down
CONTEXT.md         project glossary
deploy/            hardened systemd unit
```

## Test

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace                                  # 75 tests
cargo test -p cryptn-server --features dev --test e2e   # +9 full-stack
tests/parity/smoke.sh   # live binary smoke: needs a release build, python3, curl
```

## Honest limits

- **VPS IP blocking is the dominant real-world vector** and protocol
  innocence cannot save a throttled datacenter IP. Volume discipline and
  provider choice matter more than any wire trick here.
- **Innocence is a content discipline forever**: the envelope layer
  generates every visible field; never put user data in a plaintext JSON
  field. The censor can always read your JSON — it just never sees a
  reason to care.
- **No herd immunity**: if this becomes popular it earns its own
  signature. Small-circle use is the design point.
- **Mimicry needs maintenance**: when Ubuntu ships a new apache2, the
  persona's version string and goldens should move with it (`cryptn-persona`).
- A patient analyst correlating one user's traffic to one "abandoned" box
  could find the story odd — attribution cost is the defense, plus domain
  rotation once flagged.

## Threat model

Passive DPI (keyword/Host filtering, statistical flow classification),
active probing (path guesses, replays, scans), and casual human review.
Not in scope: endpoint compromise, global traffic-correlation adversaries,
or an adversary that decides to block all plain HTTP to that IP outright.

## License

Dual-licensed under [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE), at your option — the Rust ecosystem
standard, so CryptN stays maximally reusable.

CryptN is published for legitimate circumvention of internet censorship
and for anti-censorship research. Anyone running or using it is
responsible for the legality of doing so in their own jurisdiction.
