#!/usr/bin/env bash
# Full live smoke test: real server + client binaries, real sockets, real
# curl through the SOCKS proxy. Everything is a child of this script so the
# sandboxed shell can't reap it mid-test.
set -euo pipefail
cd "$(dirname "$0")"

BIN=../../target/release
WORK=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$WORK"' EXIT

# 1. Echo HTTP target (the "internet" for this test) on a free port.
ECHO_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
EPOCH_PORT=$ECHO_PORT python3 -c '
import http.server, socketserver, os
class Echo(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"hello from the target server: " + self.path.encode()
        self.send_response(200)
        self.send_header("Content-Type","text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
socketserver.TCPServer.allow_reuse_address = True
srv = socketserver.TCPServer(("127.0.0.1", int(os.environ["EPOCH_PORT"])), Echo)
srv.serve_forever()
' &
ECHO_PID=$!
sleep 0.5

# 2. The persona/tunnel server. CRYPTN_ALLOW_PRIVATE=1 is the documented
#    dev-only switch so the server may dial the loopback echo target; a real
#    deployment never sets it (production guard blocks private ranges).
SRV_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
CRYPTN_ALLOW_PRIVATE=1 CRYPTN_STATE_DIR="$WORK/state" CRYPTN_BIND="127.0.0.1:$SRV_PORT" "$BIN/cryptn-server" > "$WORK/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 50); do
  grep -q 'listening on' "$WORK/server.log" 2>/dev/null && break
  sleep 0.1
done

CRED=$(grep 'client credential' "$WORK/server.log" | sed 's/.*config): //')
SECRET=$(grep 'capability path' "$WORK/server.log" | sed 's#.*path: /\(.*\)/api/v1.*#\1#')
echo "== server: secret=$SECRET credential=${CRED:0:8}…"

# 3. The client (SOCKS5 on a free port).
SOCKS_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
CRYPTN_SERVER="127.0.0.1:$SRV_PORT" CRYPTN_SECRET="$SECRET" CRYPTN_CREDENTIAL="$CRED" \
  CRYPTN_SOCKS="127.0.0.1:$SOCKS_PORT" "$BIN/cryptn-client" > "$WORK/client.log" 2>&1 &
CLIENT_PID=$!
sleep 1

# 4. What a scanner sees: stock Apache.
echo '== GET / (the disguise):'
curl -s --max-time 5 "http://127.0.0.1:$SRV_PORT/" | head -c 80; echo
echo '== GET /wp-admin (probe):'
curl -s --max-time 5 -o /dev/null -w '%{http_code}\n' "http://127.0.0.1:$SRV_PORT/wp-admin/setup-config.php"
echo '== Server header:'
curl -sI --max-time 5 "http://127.0.0.1:$SRV_PORT/" | grep -i '^Server:' || true

# 5. The actual tunnel: curl through SOCKS5 to the echo target.
echo '== curl through the tunnel (SOCKS5 -> login -> tunnel -> egress -> target):'
OUT=$(curl -s --max-time 20 --socks5-hostname "127.0.0.1:$SOCKS_PORT" "http://127.0.0.1:$ECHO_PORT/through-the-tunnel")
echo "target replied: $OUT"
case "$OUT" in
  *"through-the-tunnel"*) echo "SMOKE TEST: PASS" ;;
  *) echo "SMOKE TEST: FAIL (got: $OUT)"; exit 1 ;;
esac
