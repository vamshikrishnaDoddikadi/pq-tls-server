# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.0] - 2026-03-29

### Added
- **Crypto-Agility Layer** — Pluggable provider interface for runtime algorithm management
  - Algorithm registry (`crypto_registry.c`) with dynamic provider registration, lookup, and enumeration
  - Plugin loading via `dlopen()` — drop `.so` files into a plugin directory for automatic registration
  - Policy engine with configurable minimum NIST level, hybrid preference, and classical-only fallback
  - Negotiation audit log — ring buffer recording every TLS algorithm negotiation with timestamps
  - Dynamic TLS groups string generation from registry with deduplication
  - JSON capability reporting endpoint (`/api/algorithms`) for runtime algorithm enumeration
- **ML-KEM Hybrid Benchmark Suite** — Comprehensive crypto-agility benchmarking
  - `bench_agility.c` / `bench_agility.h` — benchmarks for registry operations, provider lookups, hybrid KEM flows
  - `bench_runner.c` — standalone benchmark runner (excluded from server binary)
  - `scripts/benchmark-suite.sh` — automated benchmark execution with multiple output formats
  - `tools/benchmark-analyze.py` — Python analysis tool for benchmark result comparison
- **New KEM Providers** — Built-in providers registered via `crypto_builtins.c`
  - ML-KEM-512, ML-KEM-768, ML-KEM-1024 (lattice-based, FIPS 203)
  - X25519, P-256 (classical ECDH)
  - HQC-128, HQC-192, HQC-256 (code-based, NIST round 4 candidate)
- **New Signature Providers** — ML-DSA-44, ML-DSA-65, ML-DSA-87 (FIPS 204), Ed25519
- **Hybrid Combiners** — KDF-Concat and XOR key combination methods
- **Hybrid KEM Pairs** — Pre-defined combinations (X25519+ML-KEM-768, X25519+ML-KEM-512, X25519+ML-KEM-1024, P-256+ML-KEM-768) with per-pair TLS group validation

### Fixed
- TLS groups string included names not recognized by oqs-provider 0.7.0 (`X25519MLKEM512`, `X25519MLKEM1024`, `P256MLKEM768`) causing `SSL_CTX_set1_groups_list()` to fail — unvalidated hybrids now excluded from groups string
- Classical P-256 TLS group name changed from `P-256` to `prime256v1` (OpenSSL's accepted group name)
- Groups string generation now skips empty `tls_group` entries and deduplicates names

### Changed
- CMakeLists.txt version bumped to 2.2.0
- `pq_common` library now links `-ldl` for `dlopen()` plugin support
- COMMON_SOURCES expanded with 7 new crypto-agility source files
- BENCHMARK_SOURCES expanded with `bench_agility.c`

## [2.1.0] - 2026-03-29

### Added
- **HUD Dashboard Redesign** — Complete cyberpunk/command-center aesthetic overhaul
  - Pure black background with cyan grid overlay, glow effects, and scanline animations
  - JetBrains Mono monospace typography with uppercase tracking labels
  - 3-column HUD grid layout (3fr / 6fr / 3fr) optimized for widescreen monitors
  - Cyan (#06b6d4), fuchsia (#d946ef), emerald (#10b981) accent palette with glow shadows
  - Corner bracket decorations on cards, shimmer bars, and dot-pulse status indicators
  - Sidebar restyled with bracket navigation icons `[>]` and gradient logo `[ PQ-TLS ]`
- **New Dashboard Panels** — 9 real-data panels replacing the basic metric cards + 2 charts layout
  - TLS Configuration panel — key exchange groups, TLS version, session cache, client auth, cert expiry (from `API.getConfig()` + `API.listCerts()`)
  - PQ Adoption ring — conic-gradient ring showing post-quantum vs classical percentage
  - System Info panel — PID, workers, rate limited count
  - Connections chart — 60-point rolling line chart (cyan)
  - Throughput chart — live KB/s line chart (emerald)
  - Live Handshake Log — terminal-style log with colored `[OK]`/`[WARN]`/`[INFO]` tags from SSE stream
  - PQ vs Classical doughnut chart — fuchsia vs amber, 70% cutout
  - Data Transfer panel — live bytes in/out/total from SSE stream
  - Upstream Health panel — per-backend health bars with dot status indicators
- **Mesh Load Test Script** (`scripts/mesh-load-test.sh`) — 5-phase load testing tool
  - Phase 1: Recon — connectivity check with 5x retry, TLS cipher probe, mgmt API check, baseline snapshot
  - Phase 2: Burst — N simultaneous connections (default 50)
  - Phase 3: Sustained — continuous load at fixed concurrency for N seconds (default 20 conc x 30s)
  - Phase 4: Ramp-Up — staircase 5→40 concurrency with ok/fail/latency per level
  - Phase 5: Mesh — N simulated nodes (default 4) with different traffic patterns (steady/burst/trickle/mixed)
  - Final report with success rate, PQ vs classical counts, latency percentiles (min/avg/p50/p95/p99/max)
  - Zero dependencies beyond curl, awk, and flock — works on minimal Linux distros (Arch, Alpine)
  - Supports `--phase`, `-c`, `-d`, `--nodes`, `-r`, `-t`, `-v` flags for granular control
- **Responsive Dashboard** — 3 breakpoints for different screen sizes
  - `>1200px`: full 3-column HUD grid
  - `901–1200px`: center full-width, left+right side-by-side below
  - `<900px`: single column stack
  - `<768px`: sidebar collapses to 60px icons-only mode

### Changed
- Dashboard subtitle changed from "Command Center" to "Management"
- Chart.js colors updated: connections=#06b6d4 (cyan), throughput=#10b981 (emerald), PQ doughnut=#d946ef (fuchsia)
- Chart.js config: tension 0.4, borderWidth 1.5, pointRadius 0, doughnut cutout 70%
- Login/setup wizard overlay restyled with black background and cyan→fuchsia gradient
- All CSS custom properties renamed to cyberpunk palette (--bg-primary: #000, --accent-blue: #06b6d4, etc.)

### Removed
- Quantum Core animated SVG panel (decorative, no real data) — replaced with TLS Configuration panel
- Security Radar CSS spinner (fake blocked counter) — replaced with Data Transfer panel
- "Command Center" subtitle — replaced with "Management"
- `renderQuantumCore()`, `updateQuantumCoreState()`, `formatBytesShort()` dead code
- `.quantum-core-container`, `.radar-container`, `.radar-sweep`, `.radar-threat-count` dead CSS

### Fixed
- OQS status showed "INACTIVE" on dashboard — was reading `oqs_enabled` instead of `oqs_available` from backend API
- Load test script: curl `-w` + `|| echo` produced double output ("000000") — removed `|| fallback`
- Load test script: `bc` dependency not available on Arch Linux — replaced with `awk` for float math
- Load test script: `python3` dependency for JSON parsing — replaced with `grep`-based `json_int()`
- Load test script: `set -e` + background jobs caused premature script exit — switched to `set -uo pipefail`
- Load test script: division by zero in `progress_bar()` when total=0 — added guard
- Load test script: `seq 1 0` produced broken progress bar — replaced with for-loop char building
- Load test script: `date +%s%N` not portable — switched to `date +%s` with curl's `time_total`
- Load test script: tmpfile per request caused I/O contention — replaced with `-o /dev/null`
- Load test script: `hostname` command missing on Arch — added fallback chain (`/etc/hostname` → `$HOSTNAME` → `uname -n`)
- Load test script: stale progress in sustained phase — recalculate elapsed from wall clock after each wave

## [2.0.0] - 2026-03-25

### Added
- **Management Dashboard** — Full browser-based management UI on the health port (:9090)
  - SPA frontend with hash-based routing, dark theme, vanilla JavaScript
  - First-run setup wizard with admin account creation
  - Login with PBKDF2-SHA256 password hashing, in-memory session tokens
  - Dashboard page with live metrics, charts (Chart.js 4.4.1), SSE streaming
  - TLS/SSL configuration page — view cert details, set groups, reload certs
  - Upstream backend management — add/edit/remove backends, view health
  - Security page — runtime-reloadable rate limiting and ACL management
  - Server settings page — listen address, workers, logging configuration
  - Certificate store — upload PEM certs, generate self-signed, apply + reload
  - Real-time log viewer with level filtering, search, and download
  - Restart server from the UI with graceful shutdown via `execve()`
- **Config write-back** — Atomic INI file save (tmp + rename) from management UI
- **Runtime-reloadable settings** — Rate limiter and ACL changes apply instantly without restart
- **Certificate management API** — Generate self-signed certs, upload PEM, apply + hot-reload
- **Log streaming** — Ring buffer log collector with SSE streaming to browser
- **REST API** — Full config CRUD, cert ops, management ops with token-based auth
- **Embedded assets** — Frontend compiled into the binary via `tools/embed_assets.sh`
- Self-restart capability via `execve("/proc/self/exe", ...)`
- Backward-compatible monitoring endpoints (no auth): `/api/stats`, `/metrics`, `/health`, `/api/stream`

### Security
- Path traversal protection on all certificate file operations
- Constant-time username and password comparison (CRYPTO_memcmp)
- JSON builder with proper string escaping (control chars, RFC 8259)
- Input validation on all API endpoints
- HttpOnly + SameSite=Strict session cookies
- PBKDF2-SHA256 with 100,000 iterations for password storage

### Fixed
- Dashboard uptime resets on tab switch — now uses server-side `uptime_seconds` from SSE stream instead of client-side timer
- Dashboard empty on first load — fetches `/api/stats` immediately on init instead of waiting for first SSE event
- Demo backend BrokenPipeError spam — suppress broken pipe and connection reset errors from proxy disconnect
- Session eviction now correctly evicts the oldest session (was always slot 0)
- HTTP request parsing now loops on `recv()` until full body is received
- Thread-safe `strtok_r` used instead of `strtok` in cert generation
- Certificate serial numbers now use random values per RFC 5280
- Write errors checked before atomic rename in config save
- Certificate apply uses temp files + rename for safer operation
- ACL mode read inside mutex to prevent race condition
- Management thread is joinable (not detached) to prevent use-after-free on shutdown
- Proper cleanup ordering for mutexes and atomic flags

### Changed
- Health port now serves the full management UI instead of read-only dashboard
- `connection_manager.h` — added `restart_pending`, `start_time` fields
- `server_config.h` — added management fields (admin credentials, cert store path)
- Build system updated with management module sources and includes

## [1.0.0] - 2026-03-21

### Added
- Post-quantum TLS 1.3 termination proxy with X25519MLKEM768 hybrid key exchange
- Multi-threaded connection handling with SO_REUSEPORT
- Bidirectional HTTP/TCP proxy relay using poll()
- INI-based configuration with CLI override support
- Round-robin load balancing across multiple upstream backends
- Health/metrics HTTP endpoint (JSON)
- Systemd service with security hardening
- Docker and docker-compose support
- Certificate generation helper script
- System-wide install script
- Post-quantum crypto library: ML-KEM (FIPS 203), ML-DSA (FIPS 204), HPKE (RFC 9180), hybrid key exchange
