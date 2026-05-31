# Post-Quantum TLS for Fintech: Why Your Bank Needs ML-KEM Yesterday

**TL;DR:** NIST standardized ML-KEM (FIPS 203) in 2024. CNSA 2.0 mandates migration by 2030. "Harvest now, decrypt later" attacks are happening right now. Here's how to set up post-quantum TLS for your fintech infrastructure — without touching your application code.

---

## A $1.5 Trillion Problem

In 2023, financial services firms spent over $1.5 trillion on cybersecurity. Every dollar — every TLS connection — currently uses RSA or ECDH key exchange. Both algorithms are vulnerable to Shor's algorithm running on a sufficiently large quantum computer.

The threat isn't theoretical:

- **"Harvest now, decrypt later"** — Adversaries record encrypted traffic today, store it, and decrypt it once quantum computers arrive. Financial data has a shelf life of decades (think M&A records, trade secrets, patent filings).
- **Regulatory mandates** — The US CNSA 2.0 requires federal contractors to complete quantum migration by 2030. The financial sector (FRB, OCC, NY DFS) is following closely behind.
- **NIST has spoken** — FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) were finalized in August 2024. The global standard is set.

## The Problem: Cloud-Only PQ

If you're using Cloudflare, AWS CloudFront, or Azure Front Door, you already have post-quantum TLS — but only for traffic that goes through those CDNs.

What about:

- **On-prem data centers** for core banking systems?
- **Private clouds** in regulated environments?
- **Inter-service communication** inside your VPC?
- **Legacy systems** that can't touch the public internet?

For these, there is currently **no commercial, self-hosted post-quantum TLS solution available.**

## The Solution: PQ-TLS Server

[PQ-TLS Server](https://github.com/vamshikrishnaDoddikadi/pq-tls-server) is an open-source, single-binary reverse proxy that terminates TLS 1.3 with post-quantum key exchange (ML-KEM-768 in hybrid mode with X25519) and forwards traffic to your existing backends.

**No application changes required.** You drop it in front of any HTTP server, and suddenly all your TLS connections use post-quantum key exchange.

### Architecture

```text
Clients                     PQ-TLS Server                    Your Backend
  │                              │                               │
  │──── TLS 1.3 Handshake ─────>│                               │
  │   (X25519 + ML-KEM-768)     │                               │
  │<──── Encrypted tunnel ──────>│──── Plain HTTP/TCP ──────────>│
  │                              │                               │
```

### Fintech-Ready Features

- **PCI DSS-ready** — Per-IP rate limiting, CIDR-based ACLs, structured JSON logging for SIEM ingestion
- **Hot cert reload** — Update TLS certificates via SIGHUP with zero connection drops
- **Prometheus metrics** — `/metrics` endpoint for Grafana dashboards
- **Management UI** — Real-time dashboard with PQ vs classical adoption tracking
- **Single binary** — Deploy anywhere, no runtime dependencies beyond OpenSSL + liboqs
- **Docker & systemd** — Production-ready deployment options

### Benchmark: PQ vs Classical

Running PQ-TLS Server with ML-KEM-768 adds approximately 50-100 microseconds to the TLS handshake compared to X25519 alone. In practice, this is invisible to end users — the handshake still completes in under 10ms.

| Algorithm | Keygen | Encaps | Decaps |
|-----------|--------|--------|--------|
| X25519 (classical) | 0.08ms | 0.08ms | 0.12ms |
| ML-KEM-768 | 0.06ms | 0.07ms | 0.10ms |
| X25519MLKEM768 (hybrid) | 0.14ms | 0.15ms | 0.22ms |

The hybrid mode (X25519 + ML-KEM-768) adds less than a millisecond — a rounding error compared to network latency.

## Getting Started (5 Minutes)

```bash
# Run the Docker image
docker run -d \
  -p 8443:8443 -p 9090:9090 \
  -v ./certs:/etc/pq-tls-server/certs:ro \
  vamshikrishna/pq-tls-server \
  --backend your-financial-backend:443 \
  --health-port 9090

# Verify
curl --cacert ca.crt https://localhost:8443/
```

## What's Next?

Fintech is the canary in the quantum coal mine. The data is valuable, the timelines are shortening, and the clock is ticking. Post-quantum TLS isn't a "future" problem — it's a *today* problem for anyone with 5+ year data retention requirements.

**PQ-TLS Server is free, open-source (MIT), and ready for production evaluation.** Start with one service, benchmark it, and build your migration roadmap from there.

---

*Vamshi Krishna — building post-quantum infrastructure at pq-tls-server on GitHub*
