# PQ-TLS Server — Research Findings

> Generated: June 18, 2026 | Project: v2.2.0 | 43 C source files, ~49K LOC

---

## 1. Codebase Audit Summary

| Dimension | Score | Key Takeaways |
|-----------|-------|---------------|
| **Code Organization** | 9/10 | Clean modular structure — common/core/proxy/mgmt/security/metrics/benchmark |
| **Build System** | 8/10 | CMake + Make; compiler hardening, CTest, dual-path liboqs fallback |
| **Test Coverage** | 7/10 | 52+ test cases across 7 modules; crypto_registry tests real PQ roundtrips |
| **Docker** | 8/10 | True multi-stage, vendored deps, non-root, minimal runtime |
| **Helm Chart** | 7.5/10 | 9 templates, 187-line values.yaml — missing NetworkPolicy & PDB |
| **CI/CD** | 7/10 | Matrix builds, Docker publish — no static analysis or coverage |
| **Documentation** | 9/10 | 8 docs + 4 blog posts + 3 READMEs = exceptionally well-documented |
| **Overall** | **8/10** | Production-quality with minor polish gaps |

### Gaps to Address
- **CI:** No static analysis (cppcheck/clang-tidy), no coverage reporting
- **Helm:** Add NetworkPolicy and PodDisruptionBudget templates
- **Makefile:** Has hardcoded `/media/vamshi/SYSTEM/...` path
- **test_crypto_registry:** Separate binary, not in main test suite
- **Chart.js:** Downloaded from CDN every build instead of vendored

---

## 2. Competitive Landscape

| Solution | Type | Dashboard | Helm | Single Binary | Production Ready |
|----------|------|-----------|------|---------------|-----------------|
| **PQ-TLS Server** | Custom C proxy | ✅ | ✅ | ✅ | ✅ |
| **oqs-nginx** (OQS) | nginx + OpenSSL provider | ❌ | ❌ | ❌ | ❌ (research) |
| **wolfSSL** | Embedded C library | ❌ | ❌ | ❌ (library) | ✅ (as library) |
| **haproxy + oqs** | Proxy + provider | ❌ | ❌ | ❌ | ❌ (experimental) |
| **QuSecure QuProtect** | Agent-based orchestration | ✅ | ❌ | ❌ | ✅ |
| **SandboxAQ AQ Platform** | Enterprise PQC suite | ✅ | ✅ | ❌ | ✅ |

**Key insight:** No existing solution offers the full package — single-binary C proxy + crypto-agility registry + dashboard + Helm + systemd + Docker. **This is a blue ocean.**

---

## 3. Regulatory Timeline

| Date | Milestone |
|------|-----------|
| 2024-08-13 | NIST FIPS 203 (ML-KEM), 204 (ML-DSA), 205 (SLH-DSA) finalized |
| 2025 | CNSA 2.0: software/firmware signing must use PQ algorithms |
| 2028 | CNSA 2.0: ALL National Security Systems for web/networking/cloud |
| 2030 | CNSA 2.0: full mandate, all applications |
| 2033 | Legacy CNSA 1.0 algorithms prohibited |

---

## 4. Market Opportunity

- **PQC market:** ~$450M (2024) → **$5-9B by 2030** (40-50% CAGR)
- **TLS proxy sub-segment:** ~$250-500M by 2030 (estimated)
- **30% of large enterprises** will have started PQ migration by 2027 (Gartner)
- **Buying cycle:** 2026-2028 is the critical window for enterprise sales

### Startup Funding in PQC Space
| Company | Raised | Valuation | Focus |
|---------|--------|-----------|-------|
| SandboxAQ | ~$500M | $4.5B | Enterprise PQC platform (heavy, >$100K/yr) |
| Quantinuum | ~$650M | $5B | Quantum computing + PQC research |
| PQShield | ~$50M | — | Hardware IP, chip-level PQC |
| QuSecure | ~$28M | — | PQC TLS orchestration (multi-agent) |

---

## 5. CISO Buying Criteria — PQ-TLS Server Fit

| Criterion | Weight | PQ-TLS Score |
|-----------|--------|-------------|
| Crypto Agility | Critical | ✅ Pluggable provider registry with dlopen() |
| Hybrid + Fallback | Critical | ✅ X25519 + ML-KEM-768 hybrid (default) |
| Audit Logging | Critical | ✅ PQ negotiation stats, JSON logging |
| Deployment Ease | High | ✅ Docker + Helm + systemd |
| Dashboard/Visibility | Medium-High | ✅ 9-panel HUD SPA with SSE streaming |
| Performance | High | ⚠️ Needs published benchmark numbers |
| Vendor Support | Medium | ❌ Community only (MIT open-source) |
