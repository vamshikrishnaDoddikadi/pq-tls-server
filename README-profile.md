<!--
  GitHub Profile README
  Professional landing page for technical recruiters.
-->

<h1 align="center">Vamshi Krishna Doddikadi</h1>

<p align="center">
  <strong>Infrastructure & Security Engineer</strong><br>
  <em>Post-quantum cryptography, systems programming, AI-integrated Linux</em>
</p>

<p align="center">
  <a href="https://github.com/vamshikrishnaDoddikadi?tab=repositories"><img src="https://img.shields.io/badge/Repositories-2-38bdf8?style=flat-square" alt="Repos"></a>
  <a href="https://github.com/vamshikrishnaDoddikadi/pq-tls-server"><img src="https://img.shields.io/badge/Stars-4-34d399?style=flat-square" alt="Stars"></a>
  <a href="https://www.linkedin.com/in/vamshivivaan"><img src="https://img.shields.io/badge/LinkedIn-vamshivivaan-0a66c2?style=flat-square" alt="LinkedIn"></a>
  <a href="https://github.com/vamshikrishnaDoddikadi/pq-tls-server/blob/main/LICENSE"><img src="https://img.shields.io/badge/Open%20Source-MIT-6b7280?style=flat-square" alt="MIT"></a>
</p>

<br>

---

## Who I Am

I build infrastructure software that sits at the intersection of **cryptography**, **systems programming**, and **AI**. My work spans from C-based TLS termination proxies with NIST-standard post-quantum key exchange to fully AI-integrated Linux desktop environments.

I believe in single-binary deployments, auditable cryptographic code, and systems that respect the operator.

---

## Featured Projects

### [🛡️ PQ-TLS Server](https://github.com/vamshikrishnaDoddikadi/pq-tls-server)
**Post-Quantum TLS 1.3 Termination Reverse Proxy** — C, liboqs, OpenSSL

A production-ready reverse proxy that terminates TLS 1.3 using **ML-KEM-768 (FIPS 203)** — the NIST-standardized post-quantum key exchange — and proxies traffic to existing backends with zero application changes.

```
Clients         PQ-TLS Server (ML-KEM-768)      Your Backend
  │──── TLS 1.3 ────>│──── Plain HTTP ──────────>│
  │   (X25519+MLKEM)  │                          │
```

- Hybrid X25519 + ML-KEM-768 key exchange with automatic fallback
- Crypto-agility registry for runtime algorithm swapping
- Management dashboard with real-time PQ adoption metrics
- Single binary, Docker, systemd — zero runtime dependencies
- Hot certificate reload, rate limiting, ACLs, Prometheus metrics

**Tech stack:** C11, OpenSSL 3, liboqs, CMake, Docker, Prometheus

### [🧠 NovaOS](https://github.com/vamshikrishnaDoddikadi/NovaOs)
**AI-Integrated Arch Linux Desktop** — Arch Linux, Hyprland, Hermes Agent patterns

A custom Arch Linux spin with deep AI integration across the desktop experience. Features a voice-activated ("Nova") AGI shell, multi-provider LLM orchestration, subagent delegation, self-evolving error correction, and a memory graph powered by Obsidian + llm-wiki.

- Custom Hyprland configuration with Axeni brutalist aesthetic
- Hermes Agent-inspired multi-provider fallback architecture
- Voice interface: Kokoro TTS + faster-whisper STT
- Research pipeline: AutoResearchClaw + Karpathy style auto-research
- Rofi-based control panels for all system configuration

**Tech stack:** Arch Linux, Hyprland, C, Python, Ollama, Obsidian, Hermes Agent

---

## Technical Skills

### Languages
| Skill | Proficiency | Projects |
|-------|-------------|----------|
| **C (C11)** | Expert | PQ-TLS Server (92 source files, crypto, networking, threading) |
| **Bash** | Expert | Build scripts, CI/CD, system administration, installer automation |
| **Python** | Proficient | AI integration, backend services, build tooling |
| **TypeScript** | Proficient | Web dashboards, management UIs |
| **JavaScript** | Proficient | Browser-based SPA, Chart.js visualizations |
| **HTML/CSS** | Proficient | Landing pages, dark-theme UIs |

### Systems & Infrastructure

| Skill | Details |
|-------|---------|
| **Linux (Arch, Ubuntu, RHEL)** | System programming, kernel integration, systemd units, security hardening |
| **TLS / SSL** | TLS 1.3 protocol, certificate management, OpenSSL provider API, hot reload |
| **Post-Quantum Cryptography** | ML-KEM (FIPS 203), ML-DSA (FIPS 204), HQC, hybrid KEM combiners, crypto-agility |
| **Reverse Proxies** | Connection management, weighted load balancing, health checks, ACLs, rate limiting |
| **Docker** | Multi-stage builds, Docker Compose, Docker Hub CI publishing, layer caching |
| **Kubernetes** | Helm charts, deployments, services, ingress, HPA, ServiceMonitor |
| **Build Systems** | CMake, Make, Ninja, CI/CD pipelines (GitHub Actions) |
| **Git** | Version control, conventional commits, branching strategies, code review |

### DevOps & CI/CD

| Skill | Details |
|-------|---------|
| **GitHub Actions** | Multi-job CI/CD, Docker build/push, artifact upload, matrix builds |
| **Helm** | Chart authoring, values templating, K8s resource generation |
| **Prometheus / Grafana** | Metrics exposition, ServiceMonitor, dashboard design |
| **systemd** | Service units, security hardening, socket activation, journald |

### AI / LLM

| Skill | Details |
|-------|---------|
| **Hermes Agent Architecture** | Multi-provider fallback, skills system, memory pipeline, subagent delegation |
| **Ollama** | Local LLM deployment, model management |
| **LLM Integration Patterns** | TTS/STT pipelines, auto-research, error self-healing, resource-aware scheduling |

---

## Open Source Philosophy

- **MIT License** for all my projects — free to use, fork, and build upon
- **Single-binary deployments** — the operator should not need a PhD to run your software
- **Auditable code** — C is readable, deterministic, and has no hidden runtime
- **No vendor lock-in** — my projects work offline, air-gapped, and without SaaS dependencies

---

## Let's Connect

I'm open to opportunities in:

- **Security infrastructure engineering** — TLS, PKI, post-quantum migration
- **Systems programming** — C/Rust, networking, performance-critical services
- **Developer tooling** — Build systems, CI/CD, deployment infrastructure
- **AI infrastructure** — LLM deployment, edge AI, voice interfaces

<p align="center">
  <a href="https://github.com/vamshikrishnaDoddikadi"><img src="https://img.shields.io/badge/GitHub-vamshikrishnaDoddikadi-181717?style=for-the-badge&logo=github" alt="GitHub"></a>
  <a href="https://www.linkedin.com/in/vamshivivaan"><img src="https://img.shields.io/badge/LinkedIn-vamshivivaan-0A66C2?style=for-the-badge&logo=linkedin" alt="LinkedIn"></a>
  <br>
  <em>Always building. Always shipping.</em>
</p>
