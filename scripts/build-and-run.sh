#!/usr/bin/env bash
# ============================================================
# PQ-TLS Server — build everything and launch a local demo
#
#   scripts/build-and-run.sh
#
# 1. builds the pinned PQ dependencies into vendor/ (scripts/build-deps.sh)
# 2. builds the server and runs the unit tests
# 3. generates a demo CA + server certificate in build/demo/certs
# 4. starts the example backend (:8080) and the server (:8443, dashboard :9090)
# ============================================================
set -euo pipefail

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RED='\033[0;31m'
NC='\033[0m'; BOLD='\033[1m'

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DEMO_DIR="$ROOT/build/demo"
CERT_DIR="$DEMO_DIR/certs"

# OpenSSL >= 3.5 has native ML-KEM; older versions need oqs-provider.
PROVIDER_FLAG=""
if openssl version | awk '{split($2, v, "."); exit !(v[1] > 3 || (v[1] == 3 && v[2] >= 5))}'; then
    PROVIDER_FLAG="--no-provider"
fi

echo -e "${YELLOW}[1/4] Building pinned dependencies...${NC}"
scripts/build-deps.sh $PROVIDER_FLAG

echo -e "${YELLOW}[2/4] Building server and running unit tests...${NC}"
bash tools/embed_assets.sh >/dev/null
cmake -S . -B build -GNinja -DCMAKE_BUILD_TYPE=Release >/dev/null
ninja -C build
LD_LIBRARY_PATH="$ROOT/vendor/liboqs/lib" ./build/bin/pq-tls-tests | tail -1

echo -e "${YELLOW}[3/4] Generating demo certificates...${NC}"
mkdir -p "$CERT_DIR"
if [ ! -f "$CERT_DIR/server-cert.pem" ]; then
    openssl ecparam -genkey -name prime256v1 -out "$CERT_DIR/ca-key.pem" 2>/dev/null
    openssl req -new -x509 -key "$CERT_DIR/ca-key.pem" -out "$CERT_DIR/ca-cert.pem" \
        -days 365 -subj "/CN=PQ-TLS Demo CA/O=PQ-TLS/C=US" 2>/dev/null
    openssl ecparam -genkey -name prime256v1 -out "$CERT_DIR/server-key.pem" 2>/dev/null
    openssl req -new -key "$CERT_DIR/server-key.pem" -out "$CERT_DIR/server.csr" \
        -subj "/CN=localhost/O=PQ-TLS Server/C=US" 2>/dev/null
    openssl x509 -req -in "$CERT_DIR/server.csr" -CA "$CERT_DIR/ca-cert.pem" \
        -CAkey "$CERT_DIR/ca-key.pem" -CAcreateserial -out "$CERT_DIR/server-cert.pem" \
        -days 365 -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1") 2>/dev/null
    chmod 600 "$CERT_DIR"/*-key.pem
fi

# Persistent config (keeps dashboard credentials across restarts)
CONFIG_FILE="$DEMO_DIR/pq-tls-server.conf"
if [ ! -f "$CONFIG_FILE" ]; then
    cat >"$CONFIG_FILE" <<EOF
[listen]
address = 127.0.0.1
port = 8443

[tls]
cert = $CERT_DIR/server-cert.pem
key = $CERT_DIR/server-key.pem

[upstream]
backend = 127.0.0.1:8080

[health]
port = 9090

[rate_limit]
per_ip = 100

[mgmt]
enabled = true
localhost_only = true
EOF
    chmod 600 "$CONFIG_FILE"
fi

echo -e "${YELLOW}[4/4] Launching...${NC}"
PIDS=()
cleanup() {
    echo -e "\n${YELLOW}Shutting down...${NC}"
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
    wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

python3 examples/backend/backend.py &
PIDS+=($!)

if [ -z "$PROVIDER_FLAG" ]; then
    export OPENSSL_MODULES="$ROOT/vendor/oqs-provider/build/lib"
fi
LD_LIBRARY_PATH="$ROOT/vendor/liboqs/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
    ./build/bin/pq-tls-server --config "$CONFIG_FILE" &
PIDS+=($!)
sleep 2
if ! kill -0 "${PIDS[1]}" 2>/dev/null; then
    echo -e "${RED}Server failed to start${NC}"
    exit 1
fi

echo ""
echo -e "${BOLD}${GREEN}PQ-TLS Server is running${NC}"
echo -e "  ${CYAN}TLS proxy:${NC}   https://localhost:8443"
echo -e "  ${CYAN}Dashboard:${NC}   http://localhost:9090"
echo -e "  ${CYAN}Metrics:${NC}     http://localhost:9090/metrics"
echo -e "  ${CYAN}Backend:${NC}     http://localhost:8080"
echo ""
echo -e "  ${YELLOW}Try:${NC} curl --cacert $CERT_DIR/ca-cert.pem https://localhost:8443/"
echo -e "  Press ${RED}Ctrl+C${NC} to stop"
wait
