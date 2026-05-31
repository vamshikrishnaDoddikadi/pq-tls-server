# CNSA 2.0 Migration: A Practical Guide to Post-Quantum TLS for Defense Contractors

**TL;DR:** CNSA 2.0 mandates complete post-quantum migration for US federal contractors by 2030. Most on-prem defense systems still run classical TLS. Here's an actionable plan to start your PQ migration today.

---

## What CNSA 2.0 Actually Requires

The National Security Agency's Commercial National Security Algorithm Suite 2.0 (CNSA 2.0) lays out a phased timeline:

| Phase | Timeline | Requirement |
|-------|----------|-------------|
| **Phase 1: Preparation** | 2024-2026 | Inventory, risk assessment, pilot deployments |
| **Phase 2: Hybrid Transition** | 2026-2028 | Hybrid PQ-classical algorithms in all new systems |
| **Phase 3: PQ Native** | 2028-2030 | Full PQ-only algorithms, classical fallbacks removed |
| **Deadline** | 2030+ | No classical-only crypto for national security systems |

**We are in Phase 1 right now.** If you're a defense contractor, you should already have a PQ migration plan. If you don't, you're behind.

## The Air-Gap Problem

Most defense infrastructure runs on-prem or in air-gapped environments. Cloud-managed solutions (Cloudflare, AWS, Azure) provide post-quantum TLS, but **only for traffic that goes through their cloud.**

For a classified data center in a SCIF:

- No Cloudflare CDN to terminate TLS
- No Azure Front Door for edge termination
- No managed PQ TLS at all

You need a **self-hosted post-quantum TLS termination proxy.**

## Introducing PQ-TLS Server

[PQ-TLS Server](https://github.com/vamshikrishnaDoddikadi/pq-tls-server) is an open-source, MIT-licensed reverse proxy that terminates TLS 1.3 with post-quantum key exchange (ML-KEM-768, FIPS 203) and proxies to your existing backend services.

### Key Features for Defense Contractors

- **FIPS 203 compliant** — ML-KEM-768 is the NIST-standardized key encapsulation mechanism
- **Air-gap ready** — Single binary, zero network dependencies at runtime
- **No application changes** — Drop it in front of any HTTP service
- **Hot certificate reload** — Update certs via SIGHUP without dropping connections
- **Crypto-agility** — Pluggable algorithm registry; swap providers without recompiling
- **Prometheus metrics** — Monitor PQ vs classical adoption across your infrastructure
- **Structured JSON logging** — Feed into Splunk/Elastic for compliance audit
- **systemd + Docker** — Production-ready deployment
- **Hardened** — Non-root user, read-only filesystem, no privilege escalation

### Architecture in Your Environment

```text
[External Clients]
       │
       │ TLS 1.3 (X25519 + ML-KEM-768)  ← CNSA 2.0 compliant
       ▼
┌─────────────────┐
│  PQ-TLS Server   │  ← Single binary, runs on RHEL 8+
│  :8443           │
│  :9090 (mgmt)   │  ← Dashboard accessible only from admin network
└────────┬────────┘
         │
         │ Plain HTTP (or TLS re-encrypt)
         ▼
┌─────────────────┐
│  Backend Service │  ← Existing application, zero changes needed
└─────────────────┘
```

### What PQ-TLS Server Does NOT Do (And Why That's Good)

- It does NOT manage your PKI — use your existing CA or DoD PKI infrastructure
- It does NOT connect to external services — works 100% in air-gapped environments
- It does NOT store secrets in a database — config is a simple INI file
- It does NOT require internet access for runtime — all PQ algorithms are compiled in

## Migration Plan: 90 Days

### Week 1: Pilot

```bash
# On a RHEL 8+ test system:
git clone https://github.com/vamshikrishnaDoddikadi/pq-tls-server.git
cd pq-tls-server

# Build with vendored liboqs
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)

# Generate test certs
./scripts/gen-certs.sh

# Run in front of a test service
./build/bin/pq-tls-server \
  --cert certs/server.crt --key certs/server.key \
  --backend 127.0.0.1:8080 --health-port 9090
```

### Week 2-3: Validate

- Run the built-in `mesh-load-test.sh` to benchmark PQ vs classical handshake performance
- Verify compatibility with existing CA certificates
- Test hot certificate reload
- Measure impact on latency (expect < 1ms overhead)

### Week 4: Deploy to Staging

- Set up systemd service
- Configure structured JSON logging for Splunk/Elastic
- Point Prometheus at `/metrics` endpoint
- Deploy behind existing load balancer

### Week 5-8: Security Review

- Code audit (the repo is MIT — review the C source)
- Penetration test the PQ-TLS layer
- Verify no outbound connections
- Validate hybrid handshake with both PQ-capable and classical clients

### Week 9-12: Production Pilot

- Deploy behind one non-critical service
- Monitor for 30 days
- Document procedures for cert rotation, restart, and failover

## Why MIT License Matters for Defense

The MIT license is **key for defense adoption**:

- No CLA friction for government contractors who can't sign commercial CLAs
- Legal review is straightforward — MIT is government-friendly
- Can be built into hardened, custom builds (RHEL, SELinux, custom kernel)
- No vendor lock-in — if the project disappears, the code lives on

## The Bottom Line

CNSA 2.0 is not optional. It's a mandate with a hard deadline. PQ-TLS Server gives you a free, auditable, self-hosted path to CNSA 2.0 compliance for your TLS infrastructure — starting today.

**Start your pilot deployment this week.** The timeline is 2030, but "harvest now, decrypt later" attacks started years ago.

---

*PQ-TLS Server — MIT-licensed, open-source, CNSA 2.0 ready. GitHub: vamshikrishnaDoddikadi/pq-tls-server*
