#!/usr/bin/env bash
# =========================================================================
# Generate self-signed TLS certificates for PQ-TLS Server
# =========================================================================
# Creates a CA + server certificate suitable for testing.
# For production, use certificates from a real CA (Let's Encrypt, etc.).
#
# Usage:
#   ./gen-certs.sh                     # Output to ./certs/
#   ./gen-certs.sh /etc/pq-tls-server/certs   # Output to specific dir
# =========================================================================

set -euo pipefail

CERT_DIR="${1:-./certs}"
DAYS=365
HOSTNAME="${HOSTNAME:-localhost}"

mkdir -p "$CERT_DIR"

echo "Generating certificates in $CERT_DIR/"

# --- CA ---
echo "[1/3] Creating CA..."
openssl req -x509 -newkey rsa:4096 -sha256 \
    -days "$DAYS" -nodes \
    -keyout "$CERT_DIR/ca.key" \
    -out "$CERT_DIR/ca.crt" \
    -subj "/C=US/ST=CA/O=PQ-TLS/CN=PQ-TLS CA" \
    2>/dev/null

# --- Server key + CSR ---
echo "[2/3] Creating server certificate..."
openssl req -newkey rsa:2048 -sha256 -nodes \
    -keyout "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.csr" \
    -subj "/C=US/ST=CA/O=PQ-TLS/CN=$HOSTNAME" \
    2>/dev/null

# --- Sign with CA ---
echo "[3/3] Signing server certificate..."
cat > "$CERT_DIR/ext.cnf" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:$HOSTNAME,DNS:localhost,IP:127.0.0.1
EOF

openssl x509 -req -sha256 \
    -in "$CERT_DIR/server.csr" \
    -CA "$CERT_DIR/ca.crt" \
    -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial \
    -out "$CERT_DIR/server.crt" \
    -days "$DAYS" \
    -extfile "$CERT_DIR/ext.cnf" \
    2>/dev/null

# Cleanup
rm -f "$CERT_DIR/server.csr" "$CERT_DIR/ext.cnf" "$CERT_DIR/ca.srl"

# Set permissions
chmod 600 "$CERT_DIR/server.key" "$CERT_DIR/ca.key"
chmod 644 "$CERT_DIR/server.crt" "$CERT_DIR/ca.crt"

echo ""
echo "Certificates generated:"
echo "  CA cert:      $CERT_DIR/ca.crt"
echo "  Server cert:  $CERT_DIR/server.crt"
echo "  Server key:   $CERT_DIR/server.key"
echo ""
echo "Usage:"
echo "  pq-tls-server --cert $CERT_DIR/server.crt --key $CERT_DIR/server.key --backend 127.0.0.1:8080"
