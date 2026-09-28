# PQ-TLS Server

[![CI](https://github.com/vamshikrishnaDoddikadi/pq-tls-server/actions/workflows/ci.yml/badge.svg)](https://github.com/vamshikrishnaDoddikadi/pq-tls-server/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CLA Assistant](https://github.com/vamshikrishnaDoddikadi/pq-tls-server/actions/workflows/cla.yml/badge.svg)](.github/workflows/cla.yml)
[![Docker](https://img.shields.io/docker/pulls/vamshikrishna/pq-tls-server?label=Docker%20Pulls)]()
[![TLS 1.3](https://img.shields.io/badge/TLS-1.3-green.svg)]()
[![Post-Quantum](https://img.shields.io/badge/Post--Quantum-ML--KEM--768-purple.svg)]()
[![C](https://img.shields.io/badge/language-C-blue.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Code of Conduct](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)



**Post-Quantum TLS Termination Reverse Proxy**

A production-ready server that terminates TLS 1.3 connections using hybrid post-quantum key exchange (X25519 + ML-KEM-768, FIPS 203) and proxies traffic to your existing backend services. Drop it in front of any HTTP server to protect traffic against "harvest now, decrypt later" attacks — no application changes required.

## How it works

```
Clients                    PQ-TLS Server                    Your Backend
  │                              │                               │
  │──── TLS 1.3 Handshake ─────>│                               │
  │   (X25519 + ML-KEM-768)     │                               │
  │<──── Encrypted tunnel ──────>│──── Plain HTTP/TCP ──────────>│
  │                              │                               │
```

Clients connect with TLS 1.3 using hybrid post-quantum key exchange (X25519MLKEM768 or SecP256r1MLKEM768). The server decrypts the traffic and forwards it to your backend over plain HTTP or TCP. By default, clients that don't support post-quantum algorithms fall back to classical X25519/P-256; with `--require-pq` they are refused instead.

Every request forwarded to the backend carries authoritative `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Proto` and `X-PQ-KEM` / `X-PQ-Group` / `X-PQ-Cipher` headers; any client-supplied copies are removed, so your application can trust them.

## Features

- **Post-Quantum Key Exchange** — ML-KEM-768 (FIPS 203) hybrids with X25519 / P-256, using OpenSSL 3.5's native implementation or oqs-provider on OpenSSL 3.0–3.4
- **Enforceable PQ Policy** — `--require-pq` offers only PQ groups, forces TLS 1.3 and re-checks every connection; unsupported groups are detected at startup and reported, never silently dropped
- **Safe Header Forwarding** — Streaming HTTP/1.1 rewriter strips spoofed forwarding headers on every keep-alive request and rejects request-smuggling patterns (CL+TE, obs-fold, bad chunking)
- **Resilient Connection Handling** — Per-connection threads bounded by `max_connections`, handshake / request-head / idle timeouts, graceful drain on `SIGTERM`, IPv6
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
- **Tested End to End** — Unit suites under ASan/UBSan plus real PQ handshakes in CI on OpenSSL 3.0 + oqs-provider and OpenSSL 3.5 native

## Quick Start

```bash
# 1. Build the pinned PQ dependencies (liboqs, oqs-provider) and the server
scripts/build-deps.sh            # add --no-provider on OpenSSL >= 3.5
cmake -S . -B build -GNinja -DCMAKE_BUILD_TYPE=Release && ninja -C build

# 2. Generate test certificates and start a backend
scripts/gen-certs.sh
python3 -m http.server 8080 &

# 3. Run PQ-TLS Server (dashboard on :9090)
./build/bin/pq-tls-server -c certs/server.crt -k certs/server.key \
    -b 127.0.0.1:8080 -H 9090

# 4. Verify the key exchange — the server logs "group=X25519MLKEM768 pq=yes"
export OPENSSL_MODULES=$PWD/vendor/oqs-provider/build/lib   # OpenSSL < 3.5 only
openssl s_client -connect localhost:8443 -groups X25519MLKEM768 </dev/null
```

Or run everything (deps, build, tests, demo certificates, backend, server) with
`scripts/build-and-run.sh`.

> **Which OpenSSL?** OpenSSL 3.5+ implements the hybrid ML-KEM groups natively and
> needs nothing else. On OpenSSL 3.0–3.4 the server loads `oqsprovider.so`
> (auto-detected in `vendor/`, or via `OPENSSL_MODULES`). At startup it logs the
> groups it actually offers and warns loudly if none of them is post-quantum.

## Building

### Prerequisites

- Linux (Debian 12+/Ubuntu 22.04+, RHEL 9+)
- OpenSSL 3.0+ with development headers (3.5+ recommended: native ML-KEM)
- CMake 3.16+, Ninja or Make, GCC or Clang, git, curl
- liboqs 0.15.0 and — for OpenSSL < 3.5 — oqs-provider 0.11.0. Both are built
  by `scripts/build-deps.sh` from the versions and commit hashes pinned in
  `scripts/deps.env`.

### Build from source

```bash
scripts/build-deps.sh
cmake -S . -B build -GNinja -DCMAKE_BUILD_TYPE=Release
ninja -C build
```

The binary is at `build/bin/pq-tls-server`. `-DCMAKE_BUILD_TYPE=Debug` enables
AddressSanitizer and UndefinedBehaviorSanitizer.

### Tests

```bash
./build/bin/pq-tls-tests                     # unit tests
tests/e2e/e2e.sh build/bin/pq-tls-server     # end-to-end: real PQ handshakes,
                                             # header rewriting, timeouts, reload
```

### Install system-wide

```bash
sudo ./scripts/install.sh
```

This installs the binary to `/usr/local/bin/`, the default config to `/etc/pq-tls-server/`, and a systemd service file.

### Docker

The image is based on Debian 13 (OpenSSL 3.5, native ML-KEM) and runs the unit
and end-to-end suites during the build.

```bash
docker build -t pq-tls-server .
docker run -p 8443:8443 -p 9090:9090 \
    -v ./certs:/etc/pq-tls-server/certs:ro \
    pq-tls-server --config /etc/pq-tls-server/pq-tls-server.conf \
                  --backend host.docker.internal:8080 --health-port 9090
```

Or with docker compose:

```bash
docker compose up
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
| `-f, --config FILE` | INI config file | `/etc/pq-tls-server/pq-tls-server.conf` if present |
| `-g, --groups LIST` | TLS key exchange groups, in preference order | X25519MLKEM768:SecP256r1MLKEM768:X25519:P-256 |
| `-Q, --require-pq` | Refuse clients that cannot negotiate PQ key exchange | off |
| `-m, --mode MODE` | `http` (rewrite forwarding headers) or `tcp` (opaque relay) | http |
| `-w, --workers N` | Acceptor threads (0 = auto); connections get their own threads | 0 |
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

# IPv6
--backend [::1]:8080

# Multiple weighted backends
--backend 10.0.0.1:8080;weight=3
--backend 10.0.0.2:8080;weight=1

# Unix domain socket
--backend unix:/var/run/app.sock
```

TLS to backends (`tls://`) is not supported yet and is rejected at startup —
keep backends on a trusted network or a Unix socket.

### Post-quantum policy

| Setting | Behaviour |
|---------|-----------|
| default | Offers `X25519MLKEM768:SecP256r1MLKEM768:X25519:P-256`. PQ-capable clients (Chrome, Firefox, Edge, curl/OpenSSL 3.5, Go 1.24+) negotiate a hybrid PQ group; others fall back to a classical group. |
| `--require-pq` / `[tls] require_pq = true` | Offers only PQ groups and TLS 1.3; classical-only clients fail the handshake, and every connection is re-checked after the handshake. Refuses to start if no PQ group is available. |

Groups the loaded OpenSSL providers do not support are skipped with a warning.
The groups actually offered are logged at startup and exposed as
`tls.effective_groups` in `/api/config`, `tls_groups` in `/api/stats`, and the
`pqtls_pq_available` / `pqtls_pq_required` metrics.

### Headers sent to your backend

In `http` mode (the default) every request — including each request on a
keep-alive connection — is forwarded with:

| Header | Value |
|--------|-------|
| `X-Forwarded-For`, `X-Real-IP` | client IP address |
| `X-Forwarded-Proto` | `https` |
| `X-PQ-KEM` | negotiated group if post-quantum, otherwise `none` |
| `X-PQ-Group`, `X-PQ-Cipher` | negotiated group and cipher suite |

Client-supplied `X-Forwarded-*`, `X-Real-IP`, `Forwarded` and `X-PQ-*` headers
are removed (including `_` spellings). Requests with ambiguous framing are
answered with `400`, oversized heads with `431`, and slow heads with `408`.
Use `--mode tcp` for non-HTTP protocols.

### Management Dashboard

```bash
pq-tls-server --health-port 9090 ...
```

Open `http://localhost:9090` for the full management UI. On first visit, a setup wizard guides you through creating an admin account; it asks for the one-time **setup token** the server prints to its log at startup, so nobody else who can reach the port can claim the account first.

> The dashboard speaks plain HTTP. Keep it on a trusted network (`[mgmt] localhost_only = true` binds it to 127.0.0.1) or put it behind an authenticating TLS reverse proxy.

**Dashboard pages:**
- **Dashboard** — HUD-style 3-column grid with 9 real-data panels: TLS config, PQ adoption ring, system info, connection/throughput charts, live handshake terminal, PQ vs classical doughnut, data transfer, upstream health
- **TLS / SSL** — View cert details, configure groups, reload certificates
- **Upstreams** — Add/edit/remove backend servers, view health status
- **Security** — Rate limiting + ACL management (changes apply instantly)
- **Settings** — Listen address, workers, logging configuration (TLS and upstream changes apply live; invalid TLS settings are rolled back)
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
# Reload TLS certificates and TLS settings without downtime
kill -HUP $(cat /var/run/pq-tls-server.pid)
```

Existing connections continue with the old certificate. New connections use the reloaded certificate. If the new configuration fails to load, the previous one stays active.

### Graceful Shutdown

On `SIGTERM`/`SIGINT` the server stops accepting, lets in-flight connections finish for up to `[server] drain_timeout` (default 10 s), then closes the rest. Idle keep-alive connections are closed immediately.

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
| ML-KEM-768 | Hybrid KEM (TLS: X25519MLKEM768, SecP256r1MLKEM768) | NIST Level 3 | **Default** |
| ML-KEM-1024 | KEM | NIST Level 5 | Registry provider |
| HQC-128 | KEM (code-based) | NIST Level 1 | Registry provider (needs a liboqs build with HQC) |
| HQC-192 | KEM (code-based) | NIST Level 3 | Registry provider (needs a liboqs build with HQC) |
| HQC-256 | KEM (code-based) | NIST Level 5 | Registry provider (needs a liboqs build with HQC) |
| ML-DSA-44 | Signature | NIST Level 2 | Registry provider |
| ML-DSA-65 | Signature | NIST Level 3 | Registry provider |
| ML-DSA-87 | Signature | NIST Level 5 | Registry provider |
| X25519 | Classical ECDH | ~128-bit | Fallback |
| P-256 | Classical ECDH | ~128-bit | Registry provider |
| Ed25519 | Classical Sig | ~128-bit | Benchmark baseline |

The server uses ML-KEM-768 (FIPS 203, formerly Kyber) for key encapsulation, combined with X25519 or P-256 in the hybrid TLS groups from draft-ietf-tls-ecdhe-mlkem. An attacker must break both the classical and the post-quantum component to recover the session keys.

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

Available metrics: `pqtls_connections_total`, `pqtls_connections_active`, `pqtls_handshake_failures_total`, `pqtls_bytes_received_total`, `pqtls_bytes_sent_total`, `pqtls_pq_negotiations_total`, `pqtls_classical_negotiations_total`, `pqtls_pq_rejected_total`, `pqtls_rate_limited_total`, `pqtls_overload_rejected_total`, `pqtls_bad_requests_total`, `pqtls_pq_available`, `pqtls_pq_required`, `pqtls_max_connections`, `pqtls_workers`, `pqtls_uptime_seconds`, `pqtls_build_info`.

A useful alert: `pqtls_pq_available == 0` (the server is running without post-quantum key exchange).

## Why Post-Quantum?

Quantum computers capable of breaking RSA and ECC are expected within the next 10-20 years. The "harvest now, decrypt later" threat means adversaries can record today's encrypted traffic and decrypt it once quantum computers arrive. PQ-TLS Server protects against this by using ML-KEM-768 (standardized as FIPS 203), a lattice-based key encapsulation mechanism that is resistant to both classical and quantum attacks.

The hybrid approach (X25519 + ML-KEM-768) ensures that even if ML-KEM is somehow broken, the classical X25519 component still provides security. You get the best of both worlds.

## Community & Governance

| Resource | Link |
|----------|------|
| **Contributing** | [CONTRIBUTING.md](CONTRIBUTING.md) — how to get started |
| **Code of Conduct** | [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — community standards |
| **Security Policy** | [SECURITY.md](SECURITY.md) — vulnerability disclosure |
| **Contributor License** | [CLA.md](CLA.md) — required for code contributions |
| **Issues** | [GitHub Issues](https://github.com/vamshikrishnaDoddikadi/pq-tls-server/issues) — bugs & feature requests |
| **Discussion** | [GitHub Discussions](https://github.com/vamshikrishnaDoddikadi/pq-tls-server/discussions) — questions & ideas |
| **Changelog** | [CHANGELOG.md](CHANGELOG.md) — release history |

### Governance Model

PQ-TLS Server uses a **benevolent-dictator-for-life (BDFL)** governance model with maintainers for each subsystem. The project is maintained by:

- **Vamshi Krishna Doddikadi** — Project lead, architecture, core crypto

### Versioning

This project follows [Semantic Versioning 2.0.0](https://semver.org/). Breaking changes to public API increment the major version. The current release is **v2.3.0**.

### Roadmap

See [CHANGELOG.md](CHANGELOG.md) for what's shipped and [GitHub Projects](https://github.com/vamshikrishnaDoddikadi/pq-tls-server/projects) for upcoming work.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Author

**Vamshi Krishna Doddikadi**

[![LinkedIn](https://img.shields.io/badge/LinkedIn-vamshivivaan-0a66c2?style=flat-square&logo=linkedin)](https://www.linkedin.com/in/vamshivivaan)
[![GitHub](https://img.shields.io/badge/GitHub-vamshikrishnaDoddikadi-181717?style=flat-square&logo=github)](https://github.com/vamshikrishnaDoddikadi)

Security Engineer & Systems Programmer — Berlin, Germany.
Post-quantum cryptography, AI-integrated infrastructure, mobile security.

## Acknowledgments

Built with:

- [Open Quantum Safe (OQS)](https://openquantumsafe.org/) — liboqs + OpenSSL provider
- [OpenSSL](https://www.openssl.org/) — TLS 1.3 foundation
- NIST — post-quantum cryptography standards (FIPS 203, 204)
- AI-assisted development using Claude (Anthropic), Hermes Agent (Nous Research), and DeepSeek

### AI-Assisted Development

This project was built with the assistance of state-of-the-art AI systems:

- **Claude** (Anthropic) — code generation, security auditing, architecture design
- **Hermes Agent** (Nous Research) — autonomous multi-agent orchestration, C/C++ vulnerability auditing, systematic debugging
- **DeepSeek** — reasoning and planning for complex cryptographic implementations

All AI-generated code was reviewed, tested, and validated by the author. The 37-finding security audit that hardened this codebase was performed by an automated C/C++ vulnerability auditing agent running on Hermes.
