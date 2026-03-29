# Contributing to PQ-TLS Server

Thank you for your interest in contributing! This project aims to make post-quantum cryptography accessible for real-world server deployments.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/pq-tls-server.git`
3. Create a branch: `git checkout -b feature/your-feature`
4. Make your changes
5. Build and test: `mkdir build && cd build && cmake -DCMAKE_BUILD_TYPE=Debug .. && make`
6. Submit a pull request

## Development Setup

### Prerequisites
- Ubuntu 22.04+ (or equivalent)
- OpenSSL 3.0+ with dev headers (`libssl-dev`)
- liboqs 0.11+ ([build instructions](https://github.com/open-quantum-safe/liboqs))
- oqs-provider ([build instructions](https://github.com/open-quantum-safe/oqs-provider))
- CMake 3.16+, GCC 11+ or Clang 14+

### Debug Build
```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Debug ..
make -j$(nproc)
```

The debug build enables AddressSanitizer and UndefinedBehaviorSanitizer.

## Code Style

- C11 standard
- 4-space indentation
- `snake_case` for functions and variables
- `PQ_` or `pq_` prefix for public symbols
- Every function gets a doc comment
- Use `OPENSSL_cleanse()` for sensitive data, never plain `memset()`

## Frontend (Management Dashboard)

The dashboard is a vanilla JavaScript SPA in `src/mgmt/static/`:

- **CSS**: `css/main.css` (global palette + animations), `css/charts.css` (HUD grid layout), `css/wizard.css` (setup overlay)
- **JS**: `js/pages/*.js` (one file per page), `js/api.js` (REST client), `js/components/*.js` (shared components)
- **Theme**: Cyberpunk HUD — pure black bg, cyan/fuchsia/emerald accents, JetBrains Mono monospace, glow effects
- **Data**: All dashboard panels use real server data via SSE (`/api/stream`), REST APIs (`/api/config`, `/api/stats`, `/api/certs`), and `API.mgmtStatus()`

When modifying the frontend:
- Use the existing CSS custom properties (`--bg-primary`, `--accent-blue`, `--glow-cyan`, etc.)
- Keep all dashboard panels data-driven — no decorative/fake elements
- Test responsive breakpoints at 1200px, 900px, and 768px
- Run `bash tools/embed_assets.sh` after changes to update the embedded binary assets

## Load Testing

Use the built-in mesh load test script to validate changes under load:

```bash
# Quick burst test
bash scripts/mesh-load-test.sh --phase burst --burst 20

# Full 5-phase test
bash scripts/mesh-load-test.sh
```

The script requires only `curl`, `awk`, and `flock` — no `bc`, `python3`, or GNU coreutils needed.

## What to Contribute

- Bug fixes
- Performance improvements
- Dashboard UI improvements (maintain cyberpunk HUD aesthetic)
- New upstream backends (e.g., Unix sockets, TLS-to-backend)
- Additional PQ algorithm support
- Platform support (FreeBSD, macOS)
- Documentation improvements
- Test coverage

## Reporting Issues

Please include:
- OS and version
- OpenSSL version (`openssl version`)
- liboqs version
- Steps to reproduce
- Expected vs. actual behavior
