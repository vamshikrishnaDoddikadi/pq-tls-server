# PQ-TLS Server

[![CI](https://github.com/vamshikrishna/pq-tls-server/actions/workflows/ci.yml/badge.svg)](https://github.com/vamshikrishna/pq-tls-server/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![TLS 1.3](https://img.shields.io/badge/TLS-1.3-green.svg)]()
[![Post-Quantum](https://img.shields.io/badge/Post--Quantum-ML--KEM--768-purple.svg)]()

**Post-Quantum TLS Termination Reverse Proxy**

A production-ready server that terminates TLS 1.3 connections using post-quantum key exchange (ML-KEM-768 / Kyber) and proxies traffic to your existing backend services. Drop it in front of any HTTP server to make it quantum-resistant — no application changes required.

## How it works

```
Clients                    PQ-TLS Server                    Your Backend
  │                              │                               │
  │──── TLS 1.3 Handshake ─────>│                               │
  │   (X25519 + ML-KEM-768)     │                               │
  │<──── Encrypted tunnel ──────>│──── Plain HTTP/TCP ──────────>│
  │                              │                               │
```

Clients connect with TLS 1.3 using hybrid post-quantum key exchange (X25519MLKEM768). The server decrypts the traffic and forwards it to your backend over plain HTTP or TCP. Clients that don't support post-quantum algorithms automatically fall back to classical X25519.

## Features

- **Post-Quantum Key Exchange** — ML-KEM-768 (FIPS 203) hybrid with X25519
- **Crypto-Agility** — Pluggable provider registry with dynamic algorithm loading, policy engine, and negotiation audit log
- **Visual Management UI** — Configure everything from a browser — no config files, no CLI flags
- **HUD Dashboard** — Cyberpunk command-center UI with 3-column grid, real-time charts, SSE streaming, and glow effects
- **Certificate Management** — Upload, generate self-signed, and hot-reload certs from the UI
- **Runtime Config Changes** — Rate limiting and ACL changes apply instantly, no restart needed
- **Prometheus Metrics** — `/metrics` endpoint for Grafana/Prometheus integration
- **Built-in Benchmarking** — Benchmark ML-KEM, ML-DSA, Ed25519, and crypto-agility registry operations with `benchmark` subcommand and `bench_runner`
- **Hot Certificate Reload** — `SIGHUP` or UI button reloads TLS certs without dropping connections
- **Per-IP Rate Limiting** — Token bucket algorithm protects against connection floods
- **IP Access Control** — CIDR-based allowlist/blocklist ACLs
- **TLS Session Resumption** — Server-side session cache for faster reconnects
- **Unix Socket Backends** — Proxy to local Unix domain sockets
- **Weighted Load Balancing** — Weighted round-robin with active health checks
- **Structured JSON Logging** — Machine-parseable logs for log aggregation pipelines
- **Real-time Log Viewer** — Stream logs in the browser with level filters and search
- **PQ Negotiation Stats** — Track ML-KEM vs classical X25519 handshake ratios
- **Single Binary** — Everything embedded, zero runtime dependencies beyond OpenSSL + liboqs

## Quick Start

```bash
# 1. Generate test certificates
./scripts/gen-certs.sh

# 2. Start your backend (e.g., a local web server on port 8080)
python3 -m http.server 8080 &

# 3. Run PQ-TLS Server with dashboard
./build/bin/pq-tls-server \
    --cert certs/server.crt \
    --key certs/server.key \
    --backend 127.0.0.1:8080 \
    --health-port 9090

# 4. Open dashboard at http://localhost:9090

# 5. Test with curl
curl --cacert certs/ca.crt https://localhost:8443/
```

## Building

### Prerequisites

- Linux (Ubuntu 20.04+, Debian 11+, RHEL 8+)
- OpenSSL 3.0+ with development headers
- liboqs 0.11+ (Open Quantum Safe)
- oqs-provider for OpenSSL
- CMake 3.16+, GCC or Clang

### Build from source

```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
```

The binary is at `build/bin/pq-tls-server`.

### Install system-wide

```bash
sudo ./scripts/install.sh
```

This installs the binary to `/usr/local/bin/`, the default config to `/etc/pq-tls-server/`, and a systemd service file.

### Docker

```bash
docker build -t pq-tls-server .
docker run -p 8443:8443 -p 9090:9090 \
    -v ./certs:/etc/pq-tls-server/certs:ro \
    pq-tls-server --backend host.docker.internal:8080 --health-port 9090
```

Or with docker-compose:

```bash
docker-compose up
```

## Configuration

PQ-TLS Server supports configuration via INI file and/or CLI arguments. CLI arguments override config file values.

### Config file

```bash
pq-tls-server --config /etc/pq-tls-server/pq-tls-server.conf
```

See `etc/pq-tls-server.conf` for a fully commented example.

### CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `-c, --cert FILE` | TLS certificate (PEM) | *required* |
| `-k, --key FILE` | TLS private key (PEM) | *required* |
| `-b, --backend ADDR` | Upstream backend (repeatable) | *required* |
| `-p, --port PORT` | Listen port | 8443 |
| `-g, --groups LIST` | TLS key exchange groups | X25519MLKEM768:X25519 |
| `-w, --workers N` | Worker threads (0 = auto) | 0 |
| `-l, --log FILE` | Log file | stderr |
| `-j, --json-log` | Structured JSON logging | off |
| `-v, --verbose` | Debug logging | off |
| `-d, --daemon` | Run as daemon | off |
| `-H, --health-port N` | Dashboard/metrics port | disabled |
| `-R, --rate-limit N` | Max connections/sec per IP | disabled |
| `-S, --session-cache N` | TLS session cache size | 20000 |

### Backend formats

```bash
# Plain TCP
--backend 127.0.0.1:8080

# Multiple weighted backends
--backend 10.0.0.1:8080;weight=3
--backend 10.0.0.2:8080;weight=1

# Unix domain socket
--backend unix:/var/run/app.sock

# TLS backend
--backend tls://10.0.0.1:443
```

### Management Dashboard

```bash
pq-tls-server --health-port 9090 ...
```

Open `http://localhost:9090` for the full management UI. On first visit, a setup wizard guides you through creating an admin account.

**Dashboard pages:**
- **Dashboard** — HUD-style 3-column grid with 9 real-data panels: TLS config, PQ adoption ring, system info, connection/throughput charts, live handshake terminal, PQ vs classical doughnut, data transfer, upstream health
- **TLS / SSL** — View cert details, configure groups, reload certificates
- **Upstreams** — Add/edit/remove backend servers, view health status
- **Security** — Rate limiting + ACL management (changes apply instantly)
- **Settings** — Listen address, workers, logging configuration
- **Certificates** — Upload PEM certs, generate self-signed, apply + reload
- **Logs** — Real-time log viewer with level filters and search

**API routes** (monitoring endpoints require no auth):

| Path | Auth | Description |
|------|------|-------------|
| `/` | No | Management SPA |
| `/health` | No | `{"status":"ok"}` for load balancers |
| `/metrics` | No | Prometheus exposition format |
| `/api/stats` | No | JSON metrics snapshot |
| `/api/stream` | No | SSE real-time metrics |
| `/api/algorithms` | No | Crypto-agility registry (JSON) |
| `/api/config` | Yes | Full config as JSON |
| `/api/config/*` | Yes | Config section CRUD |
| `/api/certs/*` | Yes | Certificate management |
| `/api/mgmt/*` | Yes | Server management (restart, status) |
| `/api/logs/*` | Yes | Log streaming and history |

To embed the full SPA frontend into the binary:

```bash
bash tools/embed_assets.sh
make server  # or cmake --build build
```

### Rate Limiting

```bash
# Allow 50 connections/sec per IP, burst of 100
pq-tls-server --rate-limit 50 ...
```

Or in the config file:

```ini
[rate_limit]
per_ip = 50
burst = 100
```

### Access Control Lists

```ini
[acl]
mode = allowlist
entry = 10.0.0.0/8
entry = 192.168.1.0/24
```

### Hot Certificate Reload

```bash
# Reload TLS certificates without downtime
kill -HUP $(cat /var/run/pq-tls-server.pid)
```

Existing connections continue with the old certificate. New connections use the reloaded certificate.

### Benchmarking

```bash
# Run PQ algorithm benchmarks
pq-tls-server benchmark --iterations 5000 --format table

# Output as JSON (for CI pipelines)
pq-tls-server benchmark --format json

# Output as CSV
pq-tls-server benchmark --format csv
```

Benchmarks ML-KEM-512/768/1024 (keygen, encapsulate, decapsulate), ML-DSA-44/65 (keygen, sign, verify), and Ed25519 for comparison.

## Load Testing

PQ-TLS Server includes a built-in mesh load test script that validates server performance under realistic conditions.

```bash
# Full 5-phase test (server must be running)
bash scripts/mesh-load-test.sh

# Single phase
bash scripts/mesh-load-test.sh --phase burst

# Custom parameters
bash scripts/mesh-load-test.sh -c 40 -d 60 --nodes 8 -r 400

# Verbose (see every request)
bash scripts/mesh-load-test.sh -v --phase burst --burst 10

# Custom target
bash scripts/mesh-load-test.sh -t 192.168.1.100
```

**Test phases:**

| Phase | Description |
|-------|-------------|
| Recon | Connectivity check (5x retry), TLS cipher probe, mgmt API check, baseline snapshot |
| Burst | N simultaneous connections (default 50) |
| Sustained | Continuous load at fixed concurrency for N seconds (default 20 conc x 30s) |
| Ramp-Up | Staircase 5→40 concurrency, prints ok/fail/latency per level |
| Mesh | N simulated nodes (default 4), each with different traffic pattern |

The final report includes success rate, PQ vs classical negotiation counts, and latency percentiles (min/avg/p50/p95/p99/max).

**Cross-distro testing (WSL2):** All WSL2 distros share the same Linux VM, so the server is reachable at `127.0.0.1` from any distro. Run the server in one distro and the load test from another to simulate multi-node traffic.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        PQ-TLS Server                          │
│                                                               │
│  ┌──────────────┐   ┌───────────────────────────┐            │
│  │  Accept Loop  │   │   Worker Thread Pool       │            │
│  │  (SO_REUSEPORT)──>│   (N = CPU cores)          │            │
│  └──────────────┘   │                             │            │
│                      │  ┌──────────────────────┐  │            │
│                      │  │ ACL Check            │  │            │
│                      │  │ Rate Limiter Check   │  │            │
│                      │  │ TLS Handshake (OQS)  │  │            │
│                      │  │ PQ Negotiation Track │  │            │
│                      │  └──────────┬───────────┘  │            │
│                      │             │               │            │
│                      │  ┌──────────▼───────────┐  │  ┌───────┐│
│                      │  │ Weighted LB + Proxy   │──┼─>│Backend││
│                      │  │ (bidirectional relay) │  │  │Servers││
│                      │  └──────────────────────┘  │  └───────┘│
│                      └───────────────────────────┘            │
│                                                               │
│  ┌──────────────┐  ┌───────────────┐  ┌────────────────┐     │
│  │ Dashboard    │  │ Health Checks │  │ SIGHUP Reload  │     │
│  │ :9090       │  │ (10s interval)│  │ (cert hot-swap)│     │
│  └──────────────┘  └───────────────┘  └────────────────┘     │
└──────────────────────────────────────────────────────────────┘
```

- **Multi-threaded**: Worker threads accept and handle connections independently using `SO_REUSEPORT` for kernel-level load distribution
- **PQ Key Exchange**: X25519MLKEM768 (hybrid classical + post-quantum) with automatic fallback
- **Bidirectional proxy**: Uses `poll()` for efficient data shuttling between TLS frontend and TCP backend
- **Zero application changes**: Your backend sees normal HTTP — all PQ-TLS happens at the proxy layer

## Supported PQ Algorithms

| Algorithm | Type | Security Level | Status |
|-----------|------|---------------|--------|
| ML-KEM-512 | KEM | NIST Level 1 | Registry provider |
| ML-KEM-768 | Hybrid KEM | NIST Level 3 | **Default** |
| ML-KEM-1024 | KEM | NIST Level 5 | Registry provider |
| HQC-128 | KEM (code-based) | NIST Level 1 | Registry provider |
| HQC-192 | KEM (code-based) | NIST Level 3 | Registry provider |
| HQC-256 | KEM (code-based) | NIST Level 5 | Registry provider |
| ML-DSA-44 | Signature | NIST Level 2 | Registry provider |
| ML-DSA-65 | Signature | NIST Level 3 | Registry provider |
| ML-DSA-87 | Signature | NIST Level 5 | Registry provider |
| X25519 | Classical ECDH | ~128-bit | Fallback |
| P-256 | Classical ECDH | ~128-bit | Registry provider |
| Ed25519 | Classical Sig | ~128-bit | Benchmark baseline |

The server uses ML-KEM-768 (Kyber) for key encapsulation, combined with X25519 in a hybrid mode. This means connections are secure against both classical and quantum attacks.

All algorithms are managed through the **crypto-agility registry**, which supports runtime provider registration, dynamic plugin loading, policy-based filtering, and negotiation audit logging. Additional algorithms can be added via shared library plugins without recompiling the server.

## Project Structure

```
pq-tls-server/
├── CMakeLists.txt            # Build system
├── Makefile                  # GNU Make build system
├── Dockerfile                # Docker build
├── docker-compose.yml        # Docker Compose example
├── etc/
│   ├── pq-tls-server.conf   # Default configuration
│   └── systemd/
│       └── pq-tls-server.service
├── scripts/
│   ├── install.sh            # System installer
│   ├── gen-certs.sh          # Certificate generator
│   ├── build-and-run.sh      # All-in-one WSL build + launch
│   └── mesh-load-test.sh     # 5-phase load testing tool
├── tools/
│   └── embed_assets.sh       # Embed frontend assets into binary
└── src/
    ├── common/               # PQ crypto library + crypto-agility registry
    │   ├── pq_kem.*          # ML-KEM key encapsulation
    │   ├── pq_sig.*          # ML-DSA signatures
    │   ├── hpke.*            # Hybrid Public Key Encryption (RFC 9180)
    │   ├── hybrid_kex.*      # Hybrid key exchange
    │   ├── crypto_registry.* # Crypto-agility algorithm registry (NEW in v2.2)
    │   ├── crypto_builtins.c # Built-in provider registration (NEW in v2.2)
    │   ├── kem_mlkem.*       # ML-KEM-512/768/1024 providers (NEW in v2.2)
    │   ├── kem_classical.*   # X25519, P-256 providers (NEW in v2.2)
    │   ├── kem_hqc.*         # HQC-128/192/256 providers (NEW in v2.2)
    │   ├── sig_providers.*   # ML-DSA, Ed25519 providers (NEW in v2.2)
    │   └── hybrid_combiner.* # KDF-Concat, XOR combiners (NEW in v2.2)
    ├── core/
    │   ├── server_config.*   # Configuration parsing (INI + CLI)
    │   └── connection_manager.*  # Multi-threaded connection handling
    ├── proxy/
    │   └── http_proxy.*      # Bidirectional TCP/HTTP relay
    ├── mgmt/                 # Management dashboard (NEW in v2.0)
    │   ├── mgmt_server.*     # HTTP listener, router, static serving
    │   ├── mgmt_api.*        # REST API endpoints
    │   ├── mgmt_auth.*       # PBKDF2 auth + session management
    │   ├── config_writer.*   # INI serializer with atomic save
    │   ├── json_helpers.*    # JSON parser/builder
    │   ├── cert_manager.*    # X.509 operations
    │   ├── log_streamer.*    # Ring buffer + SSE log streaming
    │   ├── static_assets.*   # Embedded frontend assets
    │   └── static/           # Frontend SPA (HTML/CSS/JS)
    ├── dashboard/
    │   └── dashboard.*       # Legacy dashboard (fallback)
    ├── metrics/
    │   └── prometheus.*      # Prometheus metrics exporter
    ├── security/
    │   ├── rate_limiter.*    # Per-IP token bucket rate limiter
    │   └── acl.*             # IP/CIDR access control lists
    ├── benchmark/
    │   ├── bench.*           # PQ algorithm benchmarking suite
    │   ├── bench_agility.*   # Crypto-agility benchmarks (NEW in v2.2)
    │   └── bench_runner.c    # Standalone benchmark runner (NEW in v2.2)
    └── server/
        └── main.c            # Entry point
```

## systemd

```bash
# Enable and start
sudo systemctl enable pq-tls-server
sudo systemctl start pq-tls-server

# Reload certificates without restart
sudo systemctl reload pq-tls-server

# Check status
sudo systemctl status pq-tls-server

# View logs
sudo journalctl -u pq-tls-server -f
```

## Prometheus / Grafana

Scrape the `/metrics` endpoint in your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'pq-tls-server'
    static_configs:
      - targets: ['localhost:9090']
    metrics_path: '/metrics'
```

Available metrics: `pqtls_connections_total`, `pqtls_connections_active`, `pqtls_handshake_failures_total`, `pqtls_bytes_received_total`, `pqtls_bytes_sent_total`, `pqtls_pq_negotiations_total`, `pqtls_classical_negotiations_total`, `pqtls_workers`.

## Why Post-Quantum?

Quantum computers capable of breaking RSA and ECC are expected within the next 10-20 years. The "harvest now, decrypt later" threat means adversaries can record today's encrypted traffic and decrypt it once quantum computers arrive. PQ-TLS Server protects against this by using ML-KEM-768 (standardized as FIPS 203), a lattice-based key encapsulation mechanism that is resistant to both classical and quantum attacks.

The hybrid approach (X25519 + ML-KEM-768) ensures that even if ML-KEM is somehow broken, the classical X25519 component still provides security. You get the best of both worlds.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Author

**Vamshi Krishna Doddikadi** — [LinkedIn](https://www.linkedin.com/in/vamshivivaan)

## Acknowledgments

- [Open Quantum Safe (OQS)](https://openquantumsafe.org/) for liboqs and the OpenSSL provider
- [OpenSSL](https://www.openssl.org/) for the TLS foundation
- NIST for the post-quantum cryptography standardization (FIPS 203, 204)
