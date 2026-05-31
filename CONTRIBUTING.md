# Contributing to PQ-TLS Server

Thanks for your interest! PQ-TLS Server is building the foundation for post-quantum TLS infrastructure, and every contribution counts.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Quick Start](#quick-start)
- [CLA Requirement](#cla-requirement)
- [Development Setup](#development-setup)
- [Project Architecture](#project-architecture)
- [Code Style](#code-style)
- [Commit Conventions](#commit-conventions)
- [Pull Request Workflow](#pull-request-workflow)
- [Testing](#testing)
- [What to Contribute](#what-to-contribute)
- [Reporting Issues](#reporting-issues)
- [Security Issues](#security-issues)
- [Getting Help](#getting-help)

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). Be excellent to each other.

## Quick Start

```bash
# Fork → Clone → Branch
git clone https://github.com/YOUR_USERNAME/pq-tls-server.git
cd pq-tls-server
git checkout -b feature/your-feature

# Install deps
sudo apt-get install -y build-essential cmake ninja-build libssl-dev pkg-config

# Build dependencies + server
bash scripts/build-and-run.sh   # All-in-one (builds liboqs, server, tests)

# Or step by step:
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Debug ..
make -j$(nproc)
cd ..
```

Read the full [Installation Guide](INSTALL.md) for distro-specific steps.

## CLA Requirement

**All contributions over 10 lines require a signed Contributor License Agreement.**

The CLA grants the project the right to distribute your contribution under both the MIT open-source license and any future commercial licenses. You retain ownership of your contribution.

Two ways to sign:

1. **GitHub App (recommended):** When you open a PR, the CLA Assistant bot will prompt you to sign automatically.
2. **Manual:** Add `CLA_SIGNED.txt` to your PR root with:
   ```
   I, [YOUR FULL NAME], agree to the terms of the PQ-TLS Server CLA.
   GitHub Username: [YOUR USERNAME]
   Date: YYYY-MM-DD
   ```

See [CLA.md](CLA.md) for the full text. Trivial changes (typos, docs under 10 lines) don't require signing.

## Development Setup

### Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| GCC / Clang | GCC 11+ / Clang 14+ | C11 compiler |
| CMake | 3.16+ | Build system |
| OpenSSL | 3.0+ with dev headers | TLS foundation |
| liboqs | 0.11.0 | Post-quantum algorithms |
| oqs-provider | 0.7.0 | OpenSSL ↔ liboqs bridge |
| curl | Any | Chart.js download |

### Debug Build

```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Debug ..
make -j$(nproc)
```

Debug builds enable AddressSanitizer (ASan) and UndefinedBehaviorSanitizer (UBSan).

### Frontend Development

The management dashboard is a vanilla JavaScript SPA at `src/mgmt/static/`:

- **CSS:** `css/main.css` (global palette), `css/charts.css` (HUD grid)
- **JS:** `js/pages/*.js`, `js/api.js` (REST client), `js/components/*.js`
- **Embedding:** After frontend changes, run `bash tools/embed_assets.sh` to rebuild the binary

After frontend changes: `bash tools/embed_assets.sh && cmake --build build`

### Adding a New PQ Algorithm Provider

1. Implement the provider interface in `src/common/` (see `kem_mlkem.c` as a template)
2. Register the provider in `src/common/crypto_builtins.c`
3. Add benchmark support in `src/benchmark/`
4. Add the algorithm to the supported algorithms table in [README.md](README.md)

## Project Architecture

```
src/
├── common/        — PQ crypto library + crypto-agility registry
│   ├── pq_kem.*, pq_sig.*     — ML-KEM/ML-DSA operations
│   ├── crypto_registry.*      — Pluggable algorithm registry
│   ├── hybrid_kex.*           — Hybrid key exchange (X25519+MLKEM)
│   └── hpke.*                 — Hybrid Public Key Encryption
├── core/          — Server config + connection manager
├── proxy/         — Bidirectional TCP/HTTP relay
├── mgmt/          — Management dashboard (HTTP API + SPA)
├── dashboard/     — Legacy dashboard (fallback)
├── metrics/       — Prometheus exporter
├── security/      — Rate limiter + ACL
├── benchmark/     — PQ algorithm benchmarking suite
└── server/        — Entry point (main.c)
```

## Code Style

- **Language:** C11 (`-std=c11`)
- **Indentation:** 4 spaces (no tabs)
- **Naming:** `snake_case` for functions and variables
- **Prefixes:** `PQ_` or `pq_` for public symbols
- **Comments:** Every function gets a doc comment describing purpose, params, and return
- **Security:** Use `OPENSSL_cleanse()` for sensitive data, never `memset()`
- **Headers:** Always include guard with `#ifndef PQ_<MODULE>_H`

### Example

```c
/**
 * Perform hybrid key exchange (X25519 + ML-KEM-768).
 *
 * @param peer_pub   [in]  Peer's public key (combined hybrid format)
 * @param shared_sec [out] Derived shared secret (64 bytes)
 * @param kex_info   [out] Negotiation metadata
 * @return PQ_OK on success, PQ_ERR_CRYPTO on failure
 */
int pq_hybrid_exchange(const uint8_t *peer_pub, uint8_t *shared_sec,
                       struct pq_kex_info *kex_info);
```

## Commit Conventions

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short description>

<body (optional)>
<footer (optional)>
```

**Types:**
- `feat` — New feature
- `fix` — Bug fix
- `perf` — Performance improvement
- `docs` — Documentation only
- `style` — Code style (formatting, naming)
- `refactor` — Code restructure (no behavior change)
- `test` — Adding or fixing tests
- `ci` — CI/CD changes
- `chore` — Build process, tooling
- `security` — Security fix (adds CVE reference)

**Scopes:**
- `proxy` — Reverse proxy / load balancing
- `tls` — TLS handshake, cert management
- `pq` — Post-quantum algorithm integration
- `registry` — Crypto-agility registry
- `mgmt` — Management dashboard / API
- `security` — Rate limiting, ACL
- `metrics` — Prometheus / monitoring
- `cli` — CLI flags, config file parsing
- `build` — CMake, Docker, CI/CD
- `docs` — README, CONTRIBUTING, etc.

**Examples:**
```
feat(proxy): add Unix socket backend support
fix(tls): handle session cache eviction race condition
docs(pq): add ML-KEM-1024 benchmark results
perf(proxy): reduce allocator pressure in relay loop
security(mgmt): add CSRF protection to config API
```

## Pull Request Workflow

1. **Fork & Branch** — Create a feature branch from `main`
2. **Build** — `cmake -DCMAKE_BUILD_TYPE=Release .. && make -j$(nproc)`
3. **Test** — `LD_LIBRARY_PATH=vendor/liboqs/lib ./build/bin/pq-tls-tests`
4. **Sign CLA** — The CLA Assistant will prompt you if you haven't signed
5. **Open PR** — Against `main`. Use the PR template below
6. **Review** — At least one maintainer review required
7. **Merge** — Squash-merge with a conventional commit message

### PR Template

```markdown
## Description
_What does this PR do? Why is it needed?_

## Related Issue
_Closes #XYZ_

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Performance improvement
- [ ] Documentation

## Testing
- [ ] Build passes (Debug + Release)
- [ ] Tests pass
- [ ] Manual testing with mesh-load-test.sh

## Checklist
- [ ] CLA signed
- [ ] Code follows style guide
- [ ] Commits follow conventional commits
- [ ] Updated docs (if needed)
```

### PR Size Guidelines

- **Small is better.** Aim for < 400 lines changed per PR.
- **One concern per PR.** Don't mix refactors with features.
- If your change touches both C code and the frontend, consider splitting into two PRs.

## Testing

### Unit Tests

```bash
# Build and run
mkdir build && cd build && cmake -DCMAKE_BUILD_TYPE=Debug .. && make
LD_LIBRARY_PATH=vendor/liboqs/lib ./build/bin/pq-tls-tests
```

### Load Testing

```bash
# Requires server running, then run from a separate terminal:
bash scripts/mesh-load-test.sh    # 5-phase test
bash scripts/mesh-load-test.sh --phase burst   # Quick burst
```

The load test runs 5 phases: Recon → Burst → Sustained → Ramp-Up → Mesh. The final report includes success rate, PQ vs classical negotiation counts, and latency percentiles.

### CI

Every PR triggers GitHub Actions CI:
1. Build (Debug + Release) against vendored liboqs
2. Run unit tests
3. Verify binary `--help` output
4. Build Docker image
5. (Future) Run load test suite

## What to Contribute

| Priority | Area | Examples |
|----------|------|----------|
| P0 | Bug fixes | Crash in session cache, TLS handshake edge cases |
| P0 | Security hardening | Timing side channels, memory safety improvements |
| P1 | Performance | Faster relay loop, reduced allocations |
| P1 | Platform support | macOS, FreeBSD, ARM64 builds |
| P2 | Dashboard | New panels, improved HUD layout, dark theme enhancements |
| P2 | Algorithm support | Additional KEM/signature providers |
| P3 | Docs | Tutorials, deployment guides, benchmark reports |
| P3 | Tests | Coverage for edge cases, integration tests |

### Good First Issues

Look for issues tagged `good-first-issue` — these are smaller, well-scoped tasks ideal for first-time contributors.

## Reporting Issues

Include:

- OS and version (`uname -a`)
- OpenSSL version (`openssl version`)
- liboqs version
- pq-tls-server version or commit hash
- Steps to reproduce (minimal, if possible)
- Expected vs actual behavior
- Logs or terminal output

## Security Issues

**Do not file public issues for security vulnerabilities.** See [SECURITY.md](SECURITY.md) for the disclosure process.

## Getting Help

- **GitHub Issues** — Bug reports and feature requests
- **GitHub Discussions** — Questions, ideas, community discussion
- **Documentation** — [INSTALL.md](INSTALL.md), [README.md](README.md)

---

*Happy contributing! Every line you write brings post-quantum TLS closer to mainstream adoption.*
