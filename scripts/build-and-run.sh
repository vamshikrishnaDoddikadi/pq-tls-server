#!/bin/bash
# ============================================================
# PQ-TLS Server — Complete Build & Run (liboqs + oqs-provider + server)
# ============================================================
set -e
GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'; BOLD='\033[1m'

echo -e "${CYAN}"
echo '  ╔═══════════════════════════════════════════════════════╗'
echo '  ║   PQ-TLS Server — Full PQ Build & Launch              ║'
echo '  ║   ML-KEM-768 + X25519 Hybrid Key Exchange             ║'
echo '  ╚═══════════════════════════════════════════════════════╝'
echo -e "${NC}"

PROJECT="/mnt/c/Users/vamsh/Desktop/pq-tls-server"
BUILD_DIR="/tmp/pq-tls-build"
VENDOR_DIR="$PROJECT/vendor"

# ============ Step 1: Dependencies ============
echo -e "${YELLOW}[1/7] Installing dependencies...${NC}"
sudo apt-get update -qq 2>/dev/null
sudo apt-get install -y -qq gcc g++ make libssl-dev python3 cmake ninja-build git astyle 2>/dev/null
echo -e "${GREEN}  Done${NC}"

# ============ Step 2: Build liboqs (vendored) ============
if [ -f "$VENDOR_DIR/liboqs/lib/liboqs.so" ]; then
    echo -e "${GREEN}[2/7] liboqs already built in vendor/${NC}"
else
    echo -e "${YELLOW}[2/7] Building liboqs 0.11.0 into vendor/liboqs/ (~2 min)...${NC}"
    rm -rf /tmp/liboqs-src
    git clone --depth 1 --branch 0.11.0 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs-src
    cd /tmp/liboqs-src
    mkdir build && cd build

    mkdir -p "$VENDOR_DIR/liboqs"

    echo -e "  ${CYAN}Configuring...${NC}"
    if cmake -GNinja \
        -DBUILD_SHARED_LIBS=ON \
        -DCMAKE_INSTALL_PREFIX="$VENDOR_DIR/liboqs" \
        -DCMAKE_BUILD_TYPE=Release \
        -DOQS_USE_OPENSSL=ON \
        -DOPENSSL_ROOT_DIR=/usr \
        -DOPENSSL_INCLUDE_DIR=/usr/include \
        -DOPENSSL_CRYPTO_LIBRARY=/usr/lib/x86_64-linux-gnu/libcrypto.so \
        .. 2>&1 | tail -5; then
        echo -e "  ${CYAN}Compiling...${NC}"
        ninja -j$(nproc)
        ninja install
    else
        echo -e "  ${YELLOW}Retrying without OpenSSL acceleration...${NC}"
        cd /tmp/liboqs-src && rm -rf build && mkdir build && cd build
        cmake -GNinja \
            -DBUILD_SHARED_LIBS=ON \
            -DCMAKE_INSTALL_PREFIX="$VENDOR_DIR/liboqs" \
            -DCMAKE_BUILD_TYPE=Release \
            -DOQS_USE_OPENSSL=OFF \
            .. 2>&1 | tail -5
        echo -e "  ${CYAN}Compiling...${NC}"
        ninja -j$(nproc)
        ninja install
    fi

    rm -rf /tmp/liboqs-src

    if [ -f "$VENDOR_DIR/liboqs/include/oqs/oqs.h" ]; then
        echo -e "${GREEN}  liboqs installed to vendor/liboqs/${NC}"
    else
        echo -e "${RED}  liboqs install FAILED${NC}"
        exit 1
    fi
fi

# ============ Step 3: Build oqs-provider (vendored) ============
OQS_PROV_SO="$VENDOR_DIR/oqs-provider/build/lib/oqsprovider.so"
if [ -f "$OQS_PROV_SO" ]; then
    echo -e "${GREEN}[3/7] oqs-provider already built in vendor/${NC}"
else
    echo -e "${YELLOW}[3/7] Building oqs-provider 0.7.0 (~1 min)...${NC}"
    rm -rf /tmp/oqs-provider-src
    git clone --depth 1 --branch 0.7.0 https://github.com/open-quantum-safe/oqs-provider.git /tmp/oqs-provider-src
    cd /tmp/oqs-provider-src
    mkdir build && cd build

    echo -e "  ${CYAN}Configuring...${NC}"
    cmake -GNinja \
        -DCMAKE_BUILD_TYPE=Release \
        -Dliboqs_DIR="$VENDOR_DIR/liboqs/lib/cmake/liboqs" \
        .. 2>&1 | tail -5

    echo -e "  ${CYAN}Compiling...${NC}"
    ninja -j$(nproc)

    # Copy oqsprovider.so to vendor location
    mkdir -p "$VENDOR_DIR/oqs-provider/build/lib"
    cp lib/oqsprovider.so "$VENDOR_DIR/oqs-provider/build/lib/" 2>/dev/null \
        || cp oqsprov/oqsprovider.so "$VENDOR_DIR/oqs-provider/build/lib/" 2>/dev/null \
        || find . -name 'oqsprovider.so' -exec cp {} "$VENDOR_DIR/oqs-provider/build/lib/" \;

    rm -rf /tmp/oqs-provider-src

    if [ -f "$OQS_PROV_SO" ]; then
        echo -e "${GREEN}  oqs-provider installed to vendor/oqs-provider/${NC}"
    else
        echo -e "${RED}  oqs-provider build FAILED${NC}"
        exit 1
    fi
fi

# ============ Step 4: Copy & Configure ============
echo -e "${YELLOW}[4/7] Preparing build...${NC}"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cp -r "$PROJECT"/src "$BUILD_DIR"/
cp -r "$PROJECT"/tests "$BUILD_DIR"/
cp -r "$PROJECT"/examples "$BUILD_DIR"/
cp -r "$PROJECT"/tools "$BUILD_DIR"/ 2>/dev/null || true

# Download Chart.js if not present and embed frontend assets
if [ -f "$BUILD_DIR/tools/embed_assets.sh" ]; then
    CHART_JS="$BUILD_DIR/src/mgmt/static/vendor/chart.min.js"
    if [ ! -s "$CHART_JS" ] || grep -q "placeholder" "$CHART_JS" 2>/dev/null; then
        echo -e "  ${CYAN}Downloading Chart.js 4.4.1...${NC}"
        mkdir -p "$(dirname "$CHART_JS")"
        curl -sL -o "$CHART_JS" \
            https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js 2>/dev/null || true
    fi
    echo -e "  ${CYAN}Embedding frontend assets...${NC}"
    cd "$BUILD_DIR" && bash tools/embed_assets.sh 2>/dev/null || true
    cd "$BUILD_DIR"
fi

cat > "$BUILD_DIR/Makefile" << 'EOF'
PROJ     := /tmp/pq-tls-build
PROJECT  := /mnt/c/Users/vamsh/Desktop/pq-tls-server
CC       := gcc
CFLAGS   := -std=c11 -Wall -Wextra -O2 -fPIC -fstack-protector-strong -D_GNU_SOURCE
INCLUDES := -I$(PROJ)/src/common -I$(PROJ)/src/core -I$(PROJ)/src/http \
            -I$(PROJ)/src/proxy -I$(PROJ)/src/dashboard -I$(PROJ)/src/mgmt \
            -I$(PROJ)/src/metrics -I$(PROJ)/src/security -I$(PROJ)/src/benchmark \
            -I$(PROJECT)/vendor/liboqs/include
LDFLAGS  := -L$(PROJECT)/vendor/liboqs/lib -Wl,-rpath,$(PROJECT)/vendor/liboqs/lib \
            -lssl -lcrypto -loqs -lpthread -lm -ldl
TEST_LDFLAGS := -lssl -lcrypto -lpthread -lm

COMMON  := $(wildcard $(PROJ)/src/common/*.c)
CORE    := $(wildcard $(PROJ)/src/core/*.c)
HTTP    := $(wildcard $(PROJ)/src/http/*.c)
PROXY   := $(wildcard $(PROJ)/src/proxy/*.c)
DASH    := $(wildcard $(PROJ)/src/dashboard/*.c)
MGMT    := $(wildcard $(PROJ)/src/mgmt/*.c)
METRICS := $(wildcard $(PROJ)/src/metrics/*.c)
SEC     := $(wildcard $(PROJ)/src/security/*.c)
BENCH   := $(filter-out $(PROJ)/src/benchmark/bench_runner.c,$(wildcard $(PROJ)/src/benchmark/*.c))
MAIN    := $(wildcard $(PROJ)/src/server/*.c)

ALL_SRC := $(COMMON) $(CORE) $(HTTP) $(PROXY) $(DASH) $(MGMT) $(METRICS) $(SEC) $(BENCH) $(MAIN)
ALL_OBJ := $(patsubst $(PROJ)/%.c,$(PROJ)/build/%.o,$(ALL_SRC))

TEST_SRC := $(filter-out $(PROJ)/tests/test_crypto_registry.c,$(wildcard $(PROJ)/tests/*.c))
TEST_OBJ := $(patsubst $(PROJ)/%.c,$(PROJ)/build/%.o,$(TEST_SRC))
TEST_LIB := $(HTTP) $(PROJ)/src/core/epoll_reactor.c $(SEC)
TEST_LIB_OBJ := $(patsubst $(PROJ)/%.c,$(PROJ)/build/%.o,$(TEST_LIB))

.PHONY: all server tests test clean

all: server tests

server: $(ALL_OBJ)
	@mkdir -p $(PROJ)/build/bin
	$(CC) $(CFLAGS) -o $(PROJ)/build/bin/pq-tls-server $(ALL_OBJ) $(LDFLAGS)
	@echo "=== Built: pq-tls-server ==="

tests: $(TEST_OBJ) $(TEST_LIB_OBJ)
	@mkdir -p $(PROJ)/build/bin
	$(CC) $(CFLAGS) -o $(PROJ)/build/bin/pq-tls-tests $(TEST_OBJ) $(TEST_LIB_OBJ) $(TEST_LDFLAGS)
	@echo "=== Built: pq-tls-tests ==="

test: tests
	@echo "=== Running Tests ==="
	@$(PROJ)/build/bin/pq-tls-tests

$(PROJ)/build/%.o: $(PROJ)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

clean:
	rm -rf $(PROJ)/build
EOF
echo -e "${GREEN}  Done${NC}"

# ============ Step 5: Build ============
echo -e "${YELLOW}[5/7] Building server + tests...${NC}"
cd "$BUILD_DIR"

if make server 2>&1; then
    echo -e "${GREEN}  Server built!${NC}"
    SERVER_OK=1
else
    echo -e "${RED}  Server build failed${NC}"
    SERVER_OK=0
fi

if make test 2>&1; then
    echo -e "${GREEN}  All tests passed!${NC}"
else
    echo -e "${YELLOW}  Tests had issues${NC}"
fi

if [ "$SERVER_OK" -ne 1 ]; then
    echo -e "${RED}Cannot proceed without server binary${NC}"
    exit 1
fi

# ============ Step 6: Generate certs ============
echo -e "${YELLOW}[6/7] Generating TLS certificates...${NC}"
CERT_DIR="$BUILD_DIR/certs"
mkdir -p "$CERT_DIR"
openssl ecparam -genkey -name prime256v1 -out "$CERT_DIR/ca-key.pem" 2>/dev/null
openssl req -new -x509 -key "$CERT_DIR/ca-key.pem" -out "$CERT_DIR/ca-cert.pem" \
    -days 365 -subj "/CN=PQ-TLS Demo CA/O=PQ-TLS/C=US" 2>/dev/null
openssl ecparam -genkey -name prime256v1 -out "$CERT_DIR/server-key.pem" 2>/dev/null
openssl req -new -key "$CERT_DIR/server-key.pem" -out "$CERT_DIR/server.csr" \
    -subj "/CN=localhost/O=PQ-TLS Server/C=US" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
openssl x509 -req -in "$CERT_DIR/server.csr" -CA "$CERT_DIR/ca-cert.pem" \
    -CAkey "$CERT_DIR/ca-key.pem" -CAcreateserial -out "$CERT_DIR/server-cert.pem" \
    -days 365 -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1") 2>/dev/null
echo -e "${GREEN}  Certificates ready${NC}"

# ============ Step 7: Launch ============
echo -e "${YELLOW}[7/7] Launching...${NC}"

# Kill old processes on our ports
for p in 8080 8443 9090; do
    fuser -k $p/tcp 2>/dev/null || true
done
sleep 1

cleanup() {
    echo -e "\n${YELLOW}Shutting down...${NC}"
    kill $BACKEND_PID $SERVER_PID 2>/dev/null
    wait 2>/dev/null
    echo -e "${GREEN}Stopped${NC}"
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

# Backend
python3 "$BUILD_DIR/examples/backend/backend.py" &
BACKEND_PID=$!
sleep 1

# PQ-TLS Server — set OPENSSL_MODULES so OpenSSL finds oqsprovider.so,
# and LD_LIBRARY_PATH so the dlopen'd provider can find liboqs.so
OPENSSL_MODULES="$PROJECT/vendor/oqs-provider/build/lib" \
LD_LIBRARY_PATH="$PROJECT/vendor/liboqs/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
"$BUILD_DIR/build/bin/pq-tls-server" \
    --cert "$CERT_DIR/server-cert.pem" \
    --key  "$CERT_DIR/server-key.pem" \
    --backend 127.0.0.1:8080 \
    --health-port 9090 \
    --workers 2 \
    --rate-limit 100 \
    --verbose &
SERVER_PID=$!
sleep 2

if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo -e "${RED}Server failed to start${NC}"
    cat /tmp/server.log 2>/dev/null
    exit 1
fi

echo ""
echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  PQ-TLS Server is LIVE!${NC}"
echo ""
echo -e "  ${CYAN}TLS Proxy:${NC}     https://localhost:8443"
echo -e "  ${CYAN}Dashboard:${NC}     http://localhost:9090"
echo -e "  ${CYAN}Prometheus:${NC}    http://localhost:9090/metrics"
echo -e "  ${CYAN}Health:${NC}        http://localhost:9090/health"
echo -e "  ${CYAN}Backend:${NC}       http://localhost:8080"
echo ""
echo -e "  ${YELLOW}Test:${NC}  curl -k https://localhost:8443/"
echo -e "  ${YELLOW}Test:${NC}  curl -k -v https://localhost:8443/ 2>&1 | grep -i cipher"
echo ""
echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════════${NC}"
echo -e "  Press ${RED}Ctrl+C${NC} to stop"
echo ""
wait
