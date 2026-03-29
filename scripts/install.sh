#!/usr/bin/env bash
# =========================================================================
# PQ-TLS Server Installer
# =========================================================================
# Installs the PQ-TLS Server binary, configuration, and systemd service.
#
# Usage:
#   sudo ./install.sh                # Install with defaults
#   sudo ./install.sh --prefix /opt  # Custom install prefix
#
# Requirements:
#   - OpenSSL 3.0+ with headers
#   - liboqs 0.11+ (will attempt to build if not found)
#   - oqs-provider for OpenSSL
#   - CMake 3.16+, GCC/Clang, make
# =========================================================================

set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
CONF_DIR="/etc/pq-tls-server"
LOG_DIR="/var/log/pq-tls-server"
BUILD_DIR="$(cd "$(dirname "$0")/.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# --- Parse arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix) PREFIX="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: sudo $0 [--prefix /usr/local]"
            exit 0 ;;
        *) error "Unknown option: $1"; exit 1 ;;
    esac
done

# --- Check root ---
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (sudo)"
    exit 1
fi

# --- Check dependencies ---
info "Checking dependencies..."

check_cmd() {
    if ! command -v "$1" &>/dev/null; then
        error "$1 is required but not found"
        return 1
    fi
}

check_cmd cmake
check_cmd gcc || check_cmd clang
check_cmd make
check_cmd openssl

OPENSSL_VER=$(openssl version | awk '{print $2}')
info "  OpenSSL: $OPENSSL_VER"

# --- Build ---
info "Building PQ-TLS Server..."
cd "$BUILD_DIR"
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PREFIX"
make -j"$(nproc)"

# --- Install binary ---
info "Installing binary to $PREFIX/bin/"
install -Dm755 bin/pq-tls-server "$PREFIX/bin/pq-tls-server"

# --- Install config ---
if [[ ! -f "$CONF_DIR/pq-tls-server.conf" ]]; then
    info "Installing default config to $CONF_DIR/"
    install -Dm644 "$BUILD_DIR/etc/pq-tls-server.conf" "$CONF_DIR/pq-tls-server.conf"
else
    warn "Config already exists at $CONF_DIR/pq-tls-server.conf — not overwriting"
fi

# --- Create directories ---
mkdir -p "$CONF_DIR/certs"
mkdir -p "$LOG_DIR"

# --- Create service user ---
if ! id -u pq-tls &>/dev/null; then
    info "Creating system user 'pq-tls'"
    useradd --system --no-create-home --shell /usr/sbin/nologin pq-tls
fi
chown -R pq-tls:pq-tls "$LOG_DIR"

# --- Install systemd service ---
if [[ -d /etc/systemd/system ]]; then
    info "Installing systemd service"
    install -Dm644 "$BUILD_DIR/etc/systemd/pq-tls-server.service" \
        /etc/systemd/system/pq-tls-server.service
    systemctl daemon-reload
    info "  Enable with:  systemctl enable pq-tls-server"
    info "  Start with:   systemctl start pq-tls-server"
fi

echo ""
info "Installation complete!"
echo ""
echo "Next steps:"
echo "  1. Place your TLS certificate and key in $CONF_DIR/certs/"
echo "  2. Edit $CONF_DIR/pq-tls-server.conf"
echo "  3. Start the server:"
echo "       systemctl start pq-tls-server"
echo "     or:"
echo "       pq-tls-server --cert cert.pem --key key.pem --backend 127.0.0.1:8080"
echo ""
