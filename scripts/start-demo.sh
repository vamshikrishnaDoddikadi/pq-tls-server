#!/bin/bash
# ============================================================
# PQ-TLS Server Demo Launcher
# Starts the backend + PQ-TLS reverse proxy together
# ============================================================

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

# Colors
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
BOLD='\033[1m'

echo -e "${CYAN}"
echo '  ╔═══════════════════════════════════════════════════════╗'
echo '  ║     PQ-TLS Server — Post-Quantum Demo Environment    ║'
echo '  ║                                                       ║'
echo '  ║   Key Exchange: X25519 + ML-KEM-768 (Kyber)          ║'
echo '  ║   Protocol:     TLS 1.3                               ║'
echo '  ╚═══════════════════════════════════════════════════════╝'
echo -e "${NC}"

cleanup() {
    echo -e "\n${YELLOW}[demo] Shutting down...${NC}"
    [ -n "$BACKEND_PID" ] && kill "$BACKEND_PID" 2>/dev/null && echo -e "${GREEN}[demo] Backend stopped${NC}"
    [ -n "$SERVER_PID" ]  && kill "$SERVER_PID"  2>/dev/null && echo -e "${GREEN}[demo] Server stopped${NC}"
    wait 2>/dev/null
    echo -e "${GREEN}[demo] Clean shutdown complete${NC}"
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

# 1) Build if needed
if [ ! -f build/bin/pq-tls-server ]; then
    echo -e "${YELLOW}[demo] Building server...${NC}"
    make server
fi

# 2) Start backend
echo -e "${GREEN}[demo] Starting HTTP backend on :8080...${NC}"
python3 examples/backend/backend.py &
BACKEND_PID=$!
sleep 1

# Verify backend is up
if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
    echo -e "${RED}[demo] Backend failed to start!${NC}"
    exit 1
fi

# 3) Start PQ-TLS server
echo -e "${GREEN}[demo] Starting PQ-TLS server on :8443...${NC}"
OPENSSL_MODULES="$PROJECT_DIR/vendor/oqs-provider/build/lib" \
LD_LIBRARY_PATH="vendor/openssl/lib:vendor/liboqs/lib:${LD_LIBRARY_PATH:-}" \
    ./build/bin/pq-tls-server \
    --cert examples/certs/server-cert.pem \
    --key  examples/certs/server-key.pem \
    --backend 127.0.0.1:8080 \
    --health-port 9090 \
    --workers 2 \
    --rate-limit 100 \
    --verbose &
SERVER_PID=$!
sleep 2

# Verify server is up
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo -e "${RED}[demo] PQ-TLS Server failed to start! Check logs above.${NC}"
    exit 1
fi

echo ""
echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  Demo is running!${NC}"
echo ""
echo -e "  ${CYAN}PQ-TLS Proxy:${NC}    https://localhost:8443"
echo -e "  ${CYAN}Dashboard:${NC}       http://localhost:9090"
echo -e "  ${CYAN}Metrics:${NC}         http://localhost:9090/metrics"
echo -e "  ${CYAN}Health:${NC}          http://localhost:9090/health"
echo -e "  ${CYAN}Backend:${NC}         http://localhost:8080"
echo ""
echo -e "  ${YELLOW}Test with:${NC}"
echo -e "    curl -k https://localhost:8443/"
echo -e "    curl -k https://localhost:8443/health"
echo -e "    curl http://localhost:9090/metrics"
echo ""
echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════════${NC}"
echo -e "  Press ${RED}Ctrl+C${NC} to stop"
echo ""

# Wait for either process to exit
wait -n "$BACKEND_PID" "$SERVER_PID" 2>/dev/null || true
