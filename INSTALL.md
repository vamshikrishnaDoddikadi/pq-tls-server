# PQ-TLS Server — Installation & Usage Guide

[![Version](https://img.shields.io/badge/version-2.2.0-blue.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Post-Quantum](https://img.shields.io/badge/Post--Quantum-ML--KEM--768-purple.svg)]()

> Complete guide to installing, configuring, and deploying the Post-Quantum TLS Termination Reverse Proxy.

---

## Table of Contents

- [System Requirements](#system-requirements)
- [Quick Start](#quick-start)
- [Installation Methods](#installation-methods)
  - [Build from Source](#build-from-source)
  - [Docker](#docker)
  - [Docker Compose](#docker-compose)
  - [System-wide Install (systemd)](#system-wide-install-systemd)
  - [WSL (Kali / Ubuntu)](#wsl-kali--ubuntu)
- [Configuration Reference](#configuration-reference)
- [CLI Reference](#cli-reference)
- [Use Cases & Deployment Patterns](#use-cases--deployment-patterns)
- [Management Dashboard](#management-dashboard)
- [Load Testing](#load-testing)
- [Monitoring & Observability](#monitoring--observability)
- [Troubleshooting](#troubleshooting)
- [Benchmarking](#benchmarking)
- [Upgrading](#upgrading)
- [Uninstalling](#uninstalling)

---

## System Requirements

### Operating Systems

| OS | Version | Status |
|----|---------|--------|
| Ubuntu | 20.04+ | Fully supported |
| Debian | 11+ | Fully supported |
| RHEL / Rocky / Alma | 8+ | Supported |
| WSL2 (Ubuntu/Kali) | Any | Supported |
| Docker | 20.10+ | Supported |

### Dependencies

| Dependency | Minimum Version | Purpose |
|------------|----------------|---------|
| OpenSSL | 3.0 | TLS 1.3 + provider API |
| liboqs | 0.11 | Post-quantum algorithms (ML-KEM, ML-DSA) |
| oqs-provider | 0.7 | OpenSSL ↔ liboqs bridge |
| CMake | 3.16 | Build system |
| GCC or Clang | GCC 9+ / Clang 11+ | C11 compiler |
| Ninja (optional) | 1.10+ | Faster builds for liboqs |
| Python 3 | 3.8+ | Demo backend, cert scripts |
| curl | Any | Chart.js download for dashboard |

---

## Quick Start

The fastest way to get a post-quantum TLS proxy running:

```bash
# 1. Generate test certificates
./scripts/gen-certs.sh

# 2. Build the server
mkdir build && cd build && cmake -DCMAKE_BUILD_TYPE=Release .. && make -j$(nproc) && cd ..

# 3. Run (proxies to a local backend on port 8080)
python3 -m http.server 8080 &
./build/bin/pq-tls-server \
    --cert certs/server.crt --key certs/server.key \
    --backend 127.0.0.1:8080 --health-port 9090
```

Open **http://localhost:9090** for the management dashboard. Test with:

```bash
curl --cacert certs/ca.crt https://localhost:8443/
```

---

## Installation Methods

### Build from Source

This is the recommended method for development and custom deployments.

#### Step 1: Install system packages

**Ubuntu / Debian:**

```bash
sudo apt-get update
sudo apt-get install -y gcc g++ make cmake ninja-build git \
    libssl-dev pkg-config python3 curl xxd astyle
```

**RHEL / Rocky:**

```bash
sudo dnf install -y gcc gcc-c++ make cmake ninja-build git \
    openssl-devel pkgconfig python3 curl
```

#### Step 2: Build liboqs

```bash
git clone --depth 1 --branch 0.11.0 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs
cd /tmp/liboqs && mkdir build && cd build

cmake -GNinja \
    -DBUILD_SHARED_LIBS=ON \
    -DCMAKE_INSTALL_PREFIX=/path/to/pq-tls-server/vendor/liboqs \
    -DCMAKE_BUILD_TYPE=Release \
    -DOQS_USE_OPENSSL=ON \
    ..

ninja -j$(nproc)
ninja install
cd / && rm -rf /tmp/liboqs
```

Verify: `ls vendor/liboqs/include/oqs/oqs.h` should exist.

#### Step 3: Build oqs-provider

```bash
git clone --depth 1 --branch 0.7.0 https://github.com/open-quantum-safe/oqs-provider.git /tmp/oqs-provider
cd /tmp/oqs-provider && mkdir build && cd build

cmake -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -Dliboqs_DIR=/path/to/pq-tls-server/vendor/liboqs/lib/cmake/liboqs \
    ..

ninja -j$(nproc)

mkdir -p /path/to/pq-tls-server/vendor/oqs-provider/build/lib
cp lib/oqsprovider.so /path/to/pq-tls-server/vendor/oqs-provider/build/lib/
cd / && rm -rf /tmp/oqs-provider
```

#### Step 4: Build the server

```bash
cd /path/to/pq-tls-server

# (Optional) Download Chart.js and embed frontend assets into the binary
curl -sL -o src/mgmt/static/vendor/chart.min.js \
    https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js
bash tools/embed_assets.sh

# Build
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release \
    -DOQS_INCLUDE_DIR=../vendor/liboqs/include \
    -DOQS_LIBRARY=../vendor/liboqs/lib/liboqs.so \
    ..
make -j$(nproc)
```

The binary is at `build/bin/pq-tls-server`.

#### Step 5: Generate certificates

```bash
./scripts/gen-certs.sh
```

This creates `certs/ca.crt`, `certs/server.crt`, and `certs/server.key`. For production, use certificates from a real CA (Let's Encrypt, etc.).

You can also specify an output directory:

```bash
./scripts/gen-certs.sh /etc/pq-tls-server/certs
```

#### Step 6: Run

```bash
# Set environment for PQ support
export OPENSSL_MODULES=/path/to/pq-tls-server/vendor/oqs-provider/build/lib
export LD_LIBRARY_PATH=/path/to/pq-tls-server/vendor/liboqs/lib

./build/bin/pq-tls-server \
    --cert certs/server.crt \
    --key certs/server.key \
    --backend 127.0.0.1:8080 \
    --health-port 9090
```

---

### Docker

The Dockerfile uses a multi-stage build that compiles liboqs, oqs-provider, and the server from source — zero system-wide installs needed.

```bash
# Build the image
docker build -t pq-tls-server .

# Generate certs on the host (if you don't have them)
./scripts/gen-certs.sh

# Run
docker run -d \
    -p 8443:8443 \
    -p 9090:9090 \
    -v ./certs:/etc/pq-tls-server/certs:ro \
    pq-tls-server --backend host.docker.internal:8080 --health-port 9090
```

The container runs as a non-root `pq-tls` user. Exposed ports: **8443** (TLS proxy), **9090** (dashboard/metrics).

**Custom config file:**

```bash
docker run -d \
    -p 8443:8443 -p 9090:9090 \
    -v ./certs:/etc/pq-tls-server/certs:ro \
    -v ./etc/pq-tls-server.conf:/etc/pq-tls-server/pq-tls-server.conf:ro \
    pq-tls-server
```

---

### Docker Compose

The included `docker-compose.yml` sets up the PQ-TLS proxy with an example nginx backend:

```bash
# Start everything
docker-compose up -d

# View logs
docker-compose logs -f pq-tls-server

# Stop
docker-compose down
```

The default compose file:

```yaml
version: "3.8"

services:
  pq-tls-server:
    build: .
    ports:
      - "8443:8443"
      - "9090:9090"
    volumes:
      - ./certs:/etc/pq-tls-server/certs:ro
      - ./etc/pq-tls-server.conf:/etc/pq-tls-server/pq-tls-server.conf:ro
    environment:
      - OPENSSL_MODULES=/app/vendor/oqs-provider/build/lib
      - LD_LIBRARY_PATH=/app/vendor/liboqs/lib
    restart: unless-stopped
    depends_on:
      - backend

  # Replace with your actual application
  backend:
    image: nginx:alpine
    ports:
      - "8080:80"
```

To proxy to your own backend instead of nginx, replace the `backend` service or remove it and set `--backend host.docker.internal:<port>`.

---

### System-wide Install (systemd)

For production Linux deployments with automatic startup and service management:

```bash
# Build first (see "Build from Source" above), then:
sudo ./scripts/install.sh
```

This script:

1. Builds the server (if not already built)
2. Installs the binary to `/usr/local/bin/pq-tls-server`
3. Creates config directory at `/etc/pq-tls-server/`
4. Copies default config to `/etc/pq-tls-server/pq-tls-server.conf` (won't overwrite existing)
5. Creates `/etc/pq-tls-server/certs/` and `/var/log/pq-tls-server/`
6. Creates a `pq-tls` system user
7. Installs the systemd service file

**Custom prefix:**

```bash
sudo ./scripts/install.sh --prefix /opt
```

**Post-install steps:**

```bash
# 1. Place your certificates
sudo cp server.crt server.key /etc/pq-tls-server/certs/

# 2. Edit the config
sudo vim /etc/pq-tls-server/pq-tls-server.conf

# 3. Enable and start
sudo systemctl enable pq-tls-server
sudo systemctl start pq-tls-server

# 4. Check status
sudo systemctl status pq-tls-server
```

**Manage the service:**

```bash
# Reload certificates without restart (sends SIGHUP)
sudo systemctl reload pq-tls-server

# View live logs
sudo journalctl -u pq-tls-server -f

# Restart
sudo systemctl restart pq-tls-server
```

The systemd unit includes security hardening: `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, restricted capabilities (only `CAP_NET_BIND_SERVICE`), and a file descriptor limit of 65536.

---

### WSL (Kali / Ubuntu)

For development on Windows using Windows Subsystem for Linux:

```bash
# From within WSL, run the all-in-one build-and-run script:
bash /mnt/c/Users/<you>/Desktop/pq-tls-server/scripts/build-and-run.sh
```

This script handles everything automatically:

1. Installs system dependencies (`gcc`, `cmake`, `ninja-build`, `libssl-dev`, etc.)
2. Builds liboqs 0.11.0 into `vendor/liboqs/`
3. Builds oqs-provider 0.7.0 into `vendor/oqs-provider/`
4. Downloads Chart.js and embeds frontend assets
5. Compiles the server and runs tests
6. Generates test certificates
7. Starts a Python demo backend on port 8080
8. Launches the PQ-TLS server on ports 8443 (TLS) and 9090 (dashboard)

After launch, access from your Windows browser:

- **TLS Proxy:** https://localhost:8443
- **Dashboard:** http://localhost:9090
- **Prometheus:** http://localhost:9090/metrics
- **Health:** http://localhost:9090/health

Press `Ctrl+C` to stop all processes.

---

## Configuration Reference

PQ-TLS Server can be configured via an INI config file and/or CLI flags. CLI flags always override config file values.

```bash
pq-tls-server --config /etc/pq-tls-server/pq-tls-server.conf
```

### Full config file

```ini
# =========================================================================
# PQ-TLS Server Configuration
# =========================================================================

[listen]
# Network interface to bind to (0.0.0.0 = all interfaces)
address = 0.0.0.0
# TLS listen port
port = 8443

[tls]
# TLS certificate and private key (PEM format) — REQUIRED
cert = /etc/pq-tls-server/certs/server.crt
key  = /etc/pq-tls-server/certs/server.key
# Key exchange groups — controls PQ algorithm negotiation
# X25519MLKEM768 = hybrid post-quantum + classical
# X25519 = classical fallback for non-PQ clients
groups = X25519MLKEM768:X25519
# Minimum TLS version (1.2 or 1.3)
min_version = 1.3
# TLS session cache size (0 = disabled)
session_cache_size = 20000

[upstream]
# Backend servers — supports multiple entries for load balancing
# Formats: host:port, tls://host:port, unix:/path/to/sock
# Weighted: host:port;weight=3
backend = 127.0.0.1:8080
# Connection timeout to backend (milliseconds)
connect_timeout = 5000
# Idle timeout (milliseconds)
timeout = 30000

[server]
# Worker threads (0 = auto, uses CPU core count)
workers = 0
# Maximum concurrent connections
max_connections = 1024
# Run as background daemon
# daemonize = false
# pid_file = /var/run/pq-tls-server.pid

[logging]
# Log file path (empty = stderr)
# file = /var/log/pq-tls-server.log
# Log level: debug, info, warn, error
level = info
# Log each proxied request
access_log = true
# Structured JSON log output
# json = false

[health]
# Management dashboard / metrics / health HTTP port (0 = disabled)
# port = 9090

[rate_limit]
# Per-IP connection rate limit (connections/sec, 0 = disabled)
# per_ip = 50
# Token bucket burst capacity (default: 2x per_ip)
# burst = 100

[acl]
# Access control mode: disabled, allowlist, blocklist
# mode = disabled
# IP addresses or CIDR ranges (repeatable)
# entry = 10.0.0.0/8
# entry = 192.168.1.0/24

[mgmt]
# Management UI settings (auto-configured on first visit)
# enabled = true
# admin_user = admin
# admin_pass_hash = (auto-generated PBKDF2-SHA256 hash)
# cert_store = certs
```

---

## CLI Reference

| Flag | Description | Default |
|------|-------------|---------|
| `-c, --cert FILE` | TLS certificate (PEM format) | *required* |
| `-k, --key FILE` | TLS private key (PEM format) | *required* |
| `-b, --backend ADDR` | Upstream backend address (repeatable) | *required* |
| `-p, --port PORT` | TLS listen port | `8443` |
| `-g, --groups LIST` | TLS key exchange groups | `X25519MLKEM768:X25519` |
| `-w, --workers N` | Worker threads (0 = auto-detect CPUs) | `0` |
| `-l, --log FILE` | Log to file instead of stderr | stderr |
| `-j, --json-log` | Enable structured JSON logging | off |
| `-v, --verbose` | Enable debug-level logging | off |
| `-d, --daemon` | Run as background daemon | off |
| `-H, --health-port N` | Dashboard + metrics + health port | disabled |
| `-R, --rate-limit N` | Max new connections/sec per IP | disabled |
| `-S, --session-cache N` | TLS session cache size | `20000` |
| `--config FILE` | Load INI config file | none |

### Subcommands

```bash
# Run PQ algorithm benchmarks
pq-tls-server benchmark [--iterations N] [--format table|json|csv]
```

### Backend address formats

```bash
# Plain TCP
--backend 127.0.0.1:8080

# Multiple weighted backends (weighted round-robin)
--backend 10.0.0.1:8080;weight=3
--backend 10.0.0.2:8080;weight=1

# Unix domain socket
--backend unix:/var/run/app.sock

# TLS backend (re-encrypts to upstream)
--backend tls://10.0.0.1:443
```

---

## Use Cases & Deployment Patterns

### Drop-in Reverse Proxy for Any Application

Add post-quantum TLS to any existing HTTP server without code changes:

```bash
# Your app runs on port 3000
node app.js &

# PQ-TLS proxy in front of it
pq-tls-server --cert server.crt --key server.key --backend 127.0.0.1:3000
```

Works with Node.js, Python (Flask/Django/FastAPI), Go, Ruby, Java — any HTTP server.

### Microservices Load Balancer

Distribute traffic across multiple backend instances with weighted round-robin and health checks:

```bash
pq-tls-server \
    --cert server.crt --key server.key \
    --backend 10.0.0.1:8080;weight=3 \
    --backend 10.0.0.2:8080;weight=2 \
    --backend 10.0.0.3:8080;weight=1 \
    --health-port 9090
```

Backends are health-checked every 10 seconds. Unhealthy backends are automatically removed from rotation.

### Docker / Kubernetes Sidecar

Run PQ-TLS Server as a sidecar container alongside your application:

```yaml
# docker-compose.yml
services:
  pq-proxy:
    image: pq-tls-server
    ports:
      - "8443:8443"
    volumes:
      - ./certs:/etc/pq-tls-server/certs:ro
    command: ["--cert", "/etc/pq-tls-server/certs/server.crt",
              "--key", "/etc/pq-tls-server/certs/server.key",
              "--backend", "app:3000",
              "--health-port", "9090"]

  app:
    image: your-app:latest
    expose:
      - "3000"
```

In Kubernetes, deploy as a sidecar in the same pod — the proxy connects to `localhost:<port>`.

### API Gateway with Rate Limiting + ACLs

Protect your API with per-IP rate limiting and CIDR-based access control:

```bash
pq-tls-server \
    --cert server.crt --key server.key \
    --backend 127.0.0.1:8080 \
    --rate-limit 50 \
    --health-port 9090
```

Then configure ACLs via the config file:

```ini
[acl]
mode = allowlist
entry = 10.0.0.0/8
entry = 192.168.1.0/24

[rate_limit]
per_ip = 50
burst = 100
```

Rate limits and ACLs can also be changed at runtime through the management dashboard — changes apply instantly without restart.

### CI/CD Benchmarking

Track post-quantum algorithm performance over time in your CI pipeline:

```bash
# JSON output for parsing
pq-tls-server benchmark --iterations 5000 --format json > benchmark-results.json

# CSV for spreadsheets
pq-tls-server benchmark --format csv > benchmark-results.csv
```

---

## Management Dashboard

The management dashboard is a browser-based UI served on the health port. Enable it with:

```bash
pq-tls-server --health-port 9090 ...
```

### First-Run Setup

On your first visit to **http://localhost:9090**, a setup wizard guides you through creating an admin account. Credentials are stored in the config file as a PBKDF2-SHA256 hash.

### Dashboard Pages

| Page | Description |
|------|-------------|
| **Dashboard** | HUD-style 3-column grid with 9 panels: TLS config, PQ adoption ring, system info, connection/throughput charts, live handshake terminal, PQ vs classical doughnut, data transfer, upstream health. Cyberpunk aesthetic with cyan/fuchsia/emerald glow effects. |
| **TLS / SSL** | View certificate details, configure key exchange groups, reload certificates |
| **Upstreams** | Add/edit/remove backend servers, view health check status |
| **Security** | Rate limiting and ACL management — changes apply instantly, no restart |
| **Settings** | Listen address, worker threads, logging configuration |
| **Certificates** | Upload PEM certificates, generate self-signed certs, apply + hot-reload |
| **Logs** | Real-time log viewer with level filters, search, and log download |

### Dashboard Layout (v2.1.0)

The dashboard uses a 3-column HUD grid optimized for widescreen monitors:

```
STATUS BAR: connection status, uptime, version, OQS status
STATS ROW:  Active Conn | Total Conn | HS Failures | PQ Negotiated | Classical | Throughput

LEFT (3fr):              CENTER (6fr):             RIGHT (3fr):
┌─────────────────┐     ┌─────────────────────┐    ┌──────────────────┐
│ TLS Config      │     │ Connections Chart    │    │ PQ vs Classical  │
│ (groups, ver,   │     │ (60-point rolling)   │    │ (doughnut chart) │
│  cache, expiry) │     ├─────────────────────┤    ├──────────────────┤
├─────────────────┤     │ Throughput Chart     │    │ Data Transfer    │
│ PQ Adoption     │     │ (live KB/s)          │    │ (bytes in/out)   │
│ (gradient ring) │     ├─────────────────────┤    ├──────────────────┤
├─────────────────┤     │ Handshake Log        │    │ Upstream Health  │
│ System Info     │     │ (terminal-style)     │    │ (health bars)    │
└─────────────────┘     └─────────────────────┘    └──────────────────┘
```

Responsive breakpoints: full 3-column at >1200px, stacked at <900px, sidebar collapses at <768px.

### Embedding the Frontend

The management UI can be embedded directly into the binary for single-file deployment:

```bash
bash tools/embed_assets.sh
cd build && make   # or cmake --build build
```

### API Routes

Public monitoring endpoints (no authentication required):

| Path | Description |
|------|-------------|
| `/` | Management SPA |
| `/health` | `{"status":"ok"}` for load balancers |
| `/metrics` | Prometheus exposition format |
| `/api/stats` | JSON metrics snapshot |
| `/api/stream` | SSE real-time metrics stream |

Authenticated management endpoints (require login):

| Path | Description |
|------|-------------|
| `/api/config` | Full config as JSON |
| `/api/config/*` | Config section CRUD |
| `/api/certs/*` | Certificate management |
| `/api/mgmt/*` | Server management (restart, status) |
| `/api/logs/*` | Log streaming and history |

---

## Load Testing

PQ-TLS Server ships with a 5-phase mesh load test script designed to work on minimal Linux distros (no `bc`, `python3`, or GNU coreutils required — only `curl`, `awk`, and `flock`).

### Running the Load Test

```bash
# Ensure the server is running first, then:
bash scripts/mesh-load-test.sh
```

### Phases

| Phase | What It Does | Default |
|-------|-------------|---------|
| **Recon** | Connectivity check (5x retry), TLS cipher probe, mgmt API check, baseline snapshot | — |
| **Burst** | N simultaneous connections | 50 connections |
| **Sustained** | Continuous load at fixed concurrency for N seconds | 20 conc x 30s |
| **Ramp-Up** | Staircase concurrency increase, prints ok/fail/latency per level | 5→40 |
| **Mesh** | Simulated multi-node traffic with different patterns per node | 4 nodes |

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-t HOST` | Target host | `127.0.0.1` |
| `-c N` | Concurrency (sustained phase) | `20` |
| `-d N` | Duration in seconds (sustained phase) | `30` |
| `--burst N` | Burst connections | `50` |
| `--nodes N` | Mesh simulation nodes | `4` |
| `-r N` | Total requests (mesh phase) | `200` |
| `--phase NAME` | Run single phase: `recon`, `burst`, `sustained`, `ramp`, `mesh` | all |
| `-v` | Verbose — show every request | off |

### Cross-Distro Testing (WSL2)

All WSL2 distros share the same Linux VM, so the server is reachable at `127.0.0.1` from any distro:

1. Start the server in your primary WSL distro (e.g., Ubuntu/Kali):
   ```bash
   bash scripts/build-and-run.sh
   ```

2. Open a second WSL distro (e.g., Arch) and run the load test:
   ```bash
   bash /mnt/c/Users/<you>/Desktop/pq-tls-server/scripts/mesh-load-test.sh
   ```

3. Watch the dashboard at `http://localhost:9090` — you'll see real-time metric updates from the load test traffic.

### Final Report

The script prints a summary with:
- Total requests and success rate
- PQ vs classical negotiation counts (server-side, from mgmt API)
- Latency percentiles: min, avg, p50, p95, p99, max
- Server-side metric delta (connections, handshakes, bytes transferred)

---

## Monitoring & Observability

### Health Check

```bash
curl http://localhost:9090/health
# {"status":"ok"}
```

Use this endpoint for load balancer health probes (AWS ALB, Kubernetes liveness/readiness, etc.).

### Prometheus Metrics

PQ-TLS Server exposes a `/metrics` endpoint in Prometheus exposition format.

**prometheus.yml:**

```yaml
scrape_configs:
  - job_name: 'pq-tls-server'
    static_configs:
      - targets: ['localhost:9090']
    metrics_path: '/metrics'
```

**Available metrics:**

| Metric | Type | Description |
|--------|------|-------------|
| `pqtls_connections_total` | counter | Total connections accepted |
| `pqtls_connections_active` | gauge | Currently active connections |
| `pqtls_handshake_failures_total` | counter | Failed TLS handshakes |
| `pqtls_bytes_received_total` | counter | Total bytes received from clients |
| `pqtls_bytes_sent_total` | counter | Total bytes sent to clients |
| `pqtls_pq_negotiations_total` | counter | Handshakes using ML-KEM (post-quantum) |
| `pqtls_classical_negotiations_total` | counter | Handshakes using classical X25519 only |
| `pqtls_workers` | gauge | Number of active worker threads |

### Grafana

Import the Prometheus metrics above into Grafana. Useful dashboard panels:

- **Connection rate:** `rate(pqtls_connections_total[5m])`
- **Active connections:** `pqtls_connections_active`
- **PQ adoption ratio:** `pqtls_pq_negotiations_total / (pqtls_pq_negotiations_total + pqtls_classical_negotiations_total)`
- **Handshake failure rate:** `rate(pqtls_handshake_failures_total[5m])`
- **Throughput:** `rate(pqtls_bytes_sent_total[5m]) + rate(pqtls_bytes_received_total[5m])`

### JSON Stats

```bash
curl http://localhost:9090/api/stats
```

Returns a JSON snapshot of all metrics — useful for custom monitoring scripts.

### SSE Stream

```bash
curl http://localhost:9090/api/stream
```

Streams real-time metrics via Server-Sent Events. The management dashboard uses this for live chart updates.

---

## Troubleshooting

### "certificate unknown" or TLS handshake failure

**Cause:** Client doesn't trust the server certificate.

```bash
# Use --cacert to specify the CA certificate
curl --cacert certs/ca.crt https://localhost:8443/

# Or skip verification for testing only
curl -k https://localhost:8443/
```

For production, use certificates signed by a CA your clients trust (Let's Encrypt, corporate CA, etc.).

### "connection refused" on backend

**Cause:** The backend server isn't running or is on the wrong port.

```bash
# Verify your backend is listening
ss -tlnp | grep 8080

# Check the PQ-TLS server logs for backend connection errors
journalctl -u pq-tls-server -f
# or
pq-tls-server --verbose ...
```

### Port already in use

**Cause:** Another process is using port 8443 or 9090.

```bash
# Find what's using the port
sudo ss -tlnp | grep 8443

# Kill the process or choose a different port
pq-tls-server --port 8444 --health-port 9091 ...
```

### "oqsprovider.so: cannot open shared object"

**Cause:** OpenSSL can't find the OQS provider library.

```bash
# Set the OPENSSL_MODULES environment variable
export OPENSSL_MODULES=/path/to/vendor/oqs-provider/build/lib

# Also ensure liboqs is in the library path
export LD_LIBRARY_PATH=/path/to/vendor/liboqs/lib
```

For systemd, add these to the service file's `[Service]` section:

```ini
Environment=OPENSSL_MODULES=/path/to/vendor/oqs-provider/build/lib
Environment=LD_LIBRARY_PATH=/path/to/vendor/liboqs/lib
```

### "liboqs.so: cannot open shared object file"

**Cause:** The dynamic linker can't find liboqs.

```bash
# Option 1: Set LD_LIBRARY_PATH
export LD_LIBRARY_PATH=/path/to/vendor/liboqs/lib

# Option 2: Add to system library path (system-wide install)
echo "/path/to/vendor/liboqs/lib" | sudo tee /etc/ld.so.conf.d/liboqs.conf
sudo ldconfig
```

### PQ negotiation not happening (all connections show classical)

**Cause:** The client doesn't support ML-KEM / X25519MLKEM768.

```bash
# Verify with curl verbose output — look for the cipher/group
curl -k -v https://localhost:8443/ 2>&1 | grep -i 'group\|cipher'

# Check the server's configured groups
pq-tls-server --verbose ...
# Look for: "Groups: X25519MLKEM768:X25519"
```

Most standard curl/OpenSSL builds don't include PQ support. You need a PQ-enabled client (e.g., OQS-enabled OpenSSL, Chrome 124+, or Firefox with PQ enabled).

### Dashboard shows "Setup wizard" repeatedly

**Cause:** The config file isn't writable by the server process, so admin credentials can't be saved.

```bash
# Ensure the config file is writable
chmod 644 /etc/pq-tls-server/pq-tls-server.conf
chown pq-tls:pq-tls /etc/pq-tls-server/pq-tls-server.conf
```

### Server won't start in Docker

**Cause:** Missing certificates or wrong volume paths.

```bash
# Ensure certs exist and are readable
ls -la certs/

# Check container logs
docker logs <container_id>

# Verify volume mounts
docker inspect <container_id> | grep -A5 Mounts
```

---

## Benchmarking

PQ-TLS Server includes a built-in benchmarking suite for post-quantum algorithms.

### Running Benchmarks

```bash
# Table output (default)
pq-tls-server benchmark

# Custom iteration count
pq-tls-server benchmark --iterations 5000

# JSON output (for CI/CD)
pq-tls-server benchmark --format json

# CSV output (for spreadsheets)
pq-tls-server benchmark --format csv
```

### Algorithms Benchmarked

| Algorithm | Type | Operations |
|-----------|------|------------|
| ML-KEM-512 | KEM (NIST Level 1) | keygen, encapsulate, decapsulate |
| ML-KEM-768 | KEM (NIST Level 3) | keygen, encapsulate, decapsulate |
| ML-KEM-1024 | KEM (NIST Level 5) | keygen, encapsulate, decapsulate |
| ML-DSA-44 | Signature (NIST Level 2) | keygen, sign, verify |
| ML-DSA-65 | Signature (NIST Level 3) | keygen, sign, verify |
| Ed25519 | Classical Signature | keygen, sign, verify (baseline comparison) |

### Interpreting Results

- **ML-KEM-768** is the default key exchange algorithm — its encapsulate/decapsulate times directly impact handshake latency
- Compare ML-KEM times against classical Ed25519 to understand the PQ overhead
- Higher NIST levels provide stronger security but increase computation time
- Run benchmarks on your target deployment hardware for accurate numbers

---

## Upgrading

### From v2.1.0 to v2.2.0

**What's New:**

- **Crypto-Agility Layer** — Pluggable provider interface with dynamic algorithm registration, plugin loading (`dlopen`), policy engine, and negotiation audit log
- **ML-KEM Hybrid Benchmark Suite** — `bench_agility.c`, `bench_runner.c`, `benchmark-suite.sh`, `benchmark-analyze.py`
- **New Providers** — HQC-128/192/256 (code-based KEM), ML-DSA-87, P-256, plus hybrid combiners (KDF-Concat, XOR)
- **New API Endpoint** — `/api/algorithms` returns the full crypto-agility registry as JSON
- **TLS Groups Fix** — Only validated group names (X25519MLKEM768, X25519, prime256v1) are sent to OpenSSL

**Migration Steps:**

1. **Rebuild the binary** — New source files in `src/common/` and `src/benchmark/`. Re-embed and rebuild:
    ```bash
    bash tools/embed_assets.sh
    cd build && cmake -DCMAKE_BUILD_TYPE=Release .. && make -j$(nproc)
    ```

2. **No config changes required** — v2.2.0 is backward-compatible. The crypto-agility registry auto-initializes with built-in providers.

3. **Optional: add plugin directory** — To load custom algorithm plugins at runtime, create a plugin directory and place `.so` files in it. The server scans the directory on startup.

4. **CMakeLists.txt users** — If you use CMake directly, note that `pq_common` now links `-ldl`. Ensure your system has `libdl` available (standard on Linux).

**Breaking Changes:** None. v2.2.0 is fully backward-compatible.

---

### From v2.0.0 to v2.1.0

**What's New:**

- **HUD Dashboard Redesign** — Cyberpunk command-center aesthetic with 3-column grid layout, 9 real-data panels, cyan/fuchsia/emerald palette, JetBrains Mono typography, glow effects
- **Mesh Load Test Script** — 5-phase load testing tool (`scripts/mesh-load-test.sh`) with burst, sustained, ramp-up, and mesh simulation
- **New Dashboard Panels** — TLS Configuration, PQ Adoption ring, Data Transfer, Upstream Health, Live Handshake Log (terminal-style)
- **Responsive Layout** — 3 breakpoints for widescreen, tablet, and mobile

**Migration Steps:**

1. **Rebuild the binary** — Frontend assets have changed. Re-embed and rebuild:
    ```bash
    bash tools/embed_assets.sh
    cd build && make -j$(nproc)
    ```

2. **No config changes required** — v2.1.0 is a frontend-only update. Your existing config file and backend work unchanged.

3. **Clear browser cache** — The dashboard CSS/JS files have changed significantly. Hard-refresh (`Ctrl+Shift+R`) or clear cache to see the new HUD aesthetic.

**Breaking Changes:** None. v2.1.0 is fully backward-compatible.

---

### From v1.0.0 to v2.0.0

**What's New:**

- **Management Dashboard** — Full browser-based UI on the health port (replaces the read-only dashboard)
- **Certificate Management API** — Generate, upload, and hot-reload certs from the browser
- **Runtime-reloadable settings** — Rate limiter and ACL changes apply instantly, no restart
- **Config write-back** — Changes made in the UI are persisted to the INI config file
- **REST API** — Full config CRUD with token-based authentication
- **Real-time log viewer** — Stream logs in the browser with level filters and search
- **Log streaming** — Ring buffer log collector with SSE streaming
- **Embedded frontend** — Frontend assets compiled into the binary via `tools/embed_assets.sh`

**Migration Steps:**

1. **Rebuild the binary** — v2.0.0 has new source files in `src/mgmt/`. Rebuild from source.

2. **Config file is backward-compatible** — Your existing v1.0.0 config file works unchanged. Two new optional sections were added:

    ```ini
    [mgmt]
    # Auto-configured on first dashboard visit
    # enabled = true

    [health]
    # Previously just metrics, now serves the full management UI
    # port = 9090
    ```

3. **Health port behavior changed** — The health port now serves the full management UI instead of a read-only dashboard. Public monitoring endpoints (`/health`, `/metrics`, `/api/stats`, `/api/stream`) remain unauthenticated. Management endpoints require login.

4. **Re-run the install script** (for system-wide installs):

    ```bash
    sudo ./scripts/install.sh
    ```

    This updates the binary and systemd service file. Your existing config file in `/etc/pq-tls-server/` will not be overwritten.

5. **Embed frontend assets** (optional, for single-file deployment):

    ```bash
    bash tools/embed_assets.sh
    # Then rebuild
    ```

**Breaking Changes:** None. v2.0.0 is fully backward-compatible with v1.0.0 configurations and CLI flags.

---

## Uninstalling

### Binary / source install

```bash
# Remove the binary
sudo rm /usr/local/bin/pq-tls-server

# Remove the systemd service
sudo systemctl stop pq-tls-server
sudo systemctl disable pq-tls-server
sudo rm /etc/systemd/system/pq-tls-server.service
sudo systemctl daemon-reload

# Remove config and logs
sudo rm -rf /etc/pq-tls-server
sudo rm -rf /var/log/pq-tls-server

# Remove the service user
sudo userdel pq-tls
```

### Docker

```bash
# Stop and remove containers
docker-compose down

# Remove the image
docker rmi pq-tls-server
```

### Source / build directory

```bash
# Remove vendor dependencies and build artifacts
rm -rf vendor/liboqs vendor/oqs-provider build/ certs/
```

---

## Author

**Vamshi Krishna Doddikadi** — [LinkedIn](https://www.linkedin.com/in/vamshivivaan)

## License

MIT — see [LICENSE](LICENSE).
