#!/usr/bin/env bash
# =========================================================================
# End-to-end tests: real TLS handshakes through a running pq-tls-server.
#
# Usage: tests/e2e/e2e.sh [path/to/pq-tls-server]
#
# Requires: openssl CLI, curl, python3. For the post-quantum checks the
# OpenSSL CLI must be able to negotiate X25519MLKEM768: either OpenSSL >= 3.5
# or oqs-provider reachable via OPENSSL_MODULES. Without it those checks are
# skipped (the server itself is always tested).
# =========================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${1:-$ROOT/build/bin/pq-tls-server}"
WORK="$(mktemp -d)"
PORT="${E2E_PORT:-28443}"
PQ_PORT=$((PORT + 1))
BACKEND_PORT="${E2E_BACKEND_PORT:-28080}"
PASS=0
FAIL=0
SKIP=0
PIDS=()

cleanup() {
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
    wait 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

ok()   { echo "  PASS  $1"; PASS=$((PASS + 1)); }
bad()  { echo "  FAIL  $1"; FAIL=$((FAIL + 1)); }
skip() { echo "  SKIP  $1"; SKIP=$((SKIP + 1)); }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

wait_port() {
    for _ in $(seq 1 100); do
        (echo >"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

# --- client helpers --------------------------------------------------------
PROVIDER_ARGS=()
if [ -n "${OPENSSL_MODULES:-}" ] && [ -f "$OPENSSL_MODULES/oqsprovider.so" ]; then
    PROVIDER_ARGS=(-provider default -provider oqsprovider)
fi

# tls_request PORT GROUPS RAW_REQUEST -> response on stdout
tls_request() {
    printf '%b' "$3" | timeout 10 openssl s_client -quiet -connect "127.0.0.1:$1" \
        -groups "$2" "${PROVIDER_ARGS[@]}" -servername localhost 2>/dev/null
}

pq_client_available() {
    echo | timeout 5 openssl s_client -connect "127.0.0.1:$PORT" -groups X25519MLKEM768 \
        "${PROVIDER_ARGS[@]}" 2>&1 | grep -q "CONNECTED"
}

# --- fixtures --------------------------------------------------------------
echo "== setup (work dir $WORK)"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
    -subj "/CN=localhost" -keyout "$WORK/key.pem" -out "$WORK/cert.pem" 2>/dev/null
head -c 3000000 /dev/urandom >"$WORK/big.bin"

E2E_BIG_FILE="$WORK/big.bin" python3 "$ROOT/tests/e2e/echo_backend.py" "$BACKEND_PORT" &
PIDS+=($!)
wait_port "$BACKEND_PORT" || { echo "backend did not start"; exit 1; }

cat >"$WORK/server.conf" <<EOF
[listen]
address = 127.0.0.1
port = $PORT
[tls]
cert = $WORK/cert.pem
key = $WORK/key.pem
handshake_timeout = 2000
[upstream]
backend = 127.0.0.1:$BACKEND_PORT
timeout = 5000
[server]
workers = 2
max_connections = 64
drain_timeout = 3000
[logging]
level = info
EOF

"$BIN" --config "$WORK/server.conf" >"$WORK/server.log" 2>&1 &
SERVER=$!
PIDS+=($SERVER)
wait_port "$PORT" || { echo "server did not start"; cat "$WORK/server.log"; exit 1; }

URL="https://127.0.0.1:$PORT"

# --- tests -----------------------------------------------------------------
echo "== TLS & key exchange"
if pq_client_available; then
    out=$(tls_request "$PORT" X25519MLKEM768 'GET /pq HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n')
    check "PQ client negotiates X25519MLKEM768" 'grep -qi "X-PQ-KEM: X25519MLKEM768" <<<"$out"'
    HAVE_PQ=1
else
    skip "PQ client negotiates X25519MLKEM768 (no PQ-capable openssl CLI)"
    HAVE_PQ=0
fi
out=$(tls_request "$PORT" X25519 'GET /c HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n')
check "classical client still served (hybrid policy)" 'grep -qi "X-PQ-KEM: none" <<<"$out"'
check "TLS 1.2 refused by default" \
    '! echo | timeout 5 openssl s_client -connect 127.0.0.1:$PORT -tls1_2 2>/dev/null | grep -q "Cipher is ECDHE"'

echo "== header rewriting"
out=$(curl -sk "$URL/a" -H "X-Forwarded-For: 6.6.6.6" -H "X-PQ-KEM: spoofed" -H "X_Real_IP: 7.7.7.7")
check "spoofed X-Forwarded-For removed" '! grep -q "6.6.6.6" <<<"$out"'
check "spoofed X-PQ-* removed"         '! grep -q "spoofed" <<<"$out"'
check "underscore variant removed"     '! grep -q "7.7.7.7" <<<"$out"'
check "authoritative X-Forwarded-For"  'grep -qi "X-Forwarded-For: 127.0.0.1" <<<"$out"'
check "X-Forwarded-Proto: https"       'grep -qi "X-Forwarded-Proto: https" <<<"$out"'

out=$(curl -sk "$URL/one" "$URL/two" -H "X-Forwarded-For: 6.6.6.6")
check "keep-alive: every request rewritten" \
    '[ "$(grep -ci "X-Forwarded-For: 127.0.0.1" <<<"$out")" = 2 ] && ! grep -q "6.6.6.6" <<<"$out"'

out=$(curl -sk "$URL/post" --data-binary 'X-Forwarded-For: 9.9.9.9')
check "request body forwarded verbatim" 'grep -q "9.9.9.9" <<<"$out"'

out=$(tls_request "$PORT" X25519 'POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n')
check "CL+TE smuggling attempt rejected with 400" 'grep -q "400 Bad Request" <<<"$out"'

echo "== streaming"
got=$(curl -sk "$URL/big" | sha256sum | cut -d" " -f1)
want=$(sha256sum "$WORK/big.bin" | cut -d" " -f1)
check "3 MB response delivered intact" '[ "$got" = "$want" ]'

echo "== robustness"
python3 - "$PORT" <<'PY' &
import socket, sys, time
socks = [socket.create_connection(("127.0.0.1", int(sys.argv[1]))) for _ in range(20)]
time.sleep(6)
PY
IDLE=$!
sleep 0.5
start=$(date +%s%N)
code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "$URL/while-idle")
ms=$(( ($(date +%s%N) - start) / 1000000 ))
check "20 idle connections do not block service (${ms}ms)" '[ "$code" = 200 ] && [ $ms -lt 2000 ]'

start=$(date +%s)
python3 - "$PORT" <<'PY'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
s.settimeout(10)
try:
    s.recv(1)
except Exception:
    pass
PY
el=$(( $(date +%s) - start ))
check "stalled handshake cut off by handshake_timeout (${el}s)" '[ $el -le 4 ]'
wait $IDLE 2>/dev/null

kill -HUP "$SERVER"
sleep 1
code=$(curl -sk -o /dev/null -w "%{http_code}" "$URL/after-reload")
check "SIGHUP reload keeps serving" '[ "$code" = 200 ] && grep -q "TLS configuration reloaded" "$WORK/server.log"'

echo "== --require-pq"
sed -e "s/^port = $PORT/port = $PQ_PORT/" -e 's/^\[tls\]/[tls]\nrequire_pq = true/' \
    "$WORK/server.conf" >"$WORK/pq.conf"
"$BIN" --config "$WORK/pq.conf" >"$WORK/pq.log" 2>&1 &
PQ_SERVER=$!
PIDS+=($PQ_SERVER)
if wait_port "$PQ_PORT"; then
    out=$(tls_request "$PQ_PORT" X25519 'GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n')
    check "classical-only client refused" '! grep -q "200 OK" <<<"$out"'
    if [ "$HAVE_PQ" = 1 ]; then
        out=$(tls_request "$PQ_PORT" X25519MLKEM768 'GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n')
        check "PQ client accepted" 'grep -q "200 OK" <<<"$out"'
    else
        skip "PQ client accepted (no PQ-capable openssl CLI)"
    fi
elif grep -q "no post-quantum key exchange is available" "$WORK/pq.log"; then
    ok "--require-pq refuses to start without PQ support"
else
    bad "--require-pq server failed unexpectedly"; cat "$WORK/pq.log"
fi

echo "== shutdown"
kill -TERM "$SERVER"
for _ in $(seq 1 50); do kill -0 "$SERVER" 2>/dev/null || break; sleep 0.1; done
check "SIGTERM: graceful exit" '! kill -0 $SERVER 2>/dev/null && wait $SERVER'

echo
echo "e2e: $PASS passed, $FAIL failed, $SKIP skipped"
if [ "$FAIL" -ne 0 ]; then
    echo "--- server log ---"; tail -40 "$WORK/server.log"
    exit 1
fi
