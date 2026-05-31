# Security Policy

PQ-TLS Server provides cryptographic security for TLS connections using post-quantum algorithms. We take security vulnerabilities seriously.

## Reporting a Vulnerability

**Do not file a public GitHub issue for security vulnerabilities.**

Please report vulnerabilities via one of these channels:

1. **GitHub Private Vulnerability Reporting** — Use the "Report a vulnerability" button on the repository's Security tab
2. **Email** — vamshikrishna.doddikadi@example.com (replace with your actual email)

You should receive a response within 48 hours. If you don't, follow up.

## What to Include

- Description of the vulnerability
- Steps to reproduce (PoC, test case, or exploit code)
- Affected versions and configurations
- Impact assessment (what an attacker could achieve)
- Any suggested fix, if known

## Scope

In-scope:
- PQ-TLS server binary and runtime
- Management dashboard and REST API
- Build system and CI/CD pipeline
- Crypto-agility provider registry
- All supported post-quantum algorithm integrations (ML-KEM, ML-DSA, HQC)

Out-of-scope:
- Third-party dependencies (OpenSSL, liboqs, oqs-provider) — report those to their respective projects
- Infrastructure running pq-tls-server (network, host OS, firewalls)

## Our Commitment

- **Acknowledgment** — within 48 hours
- **Initial assessment** — within 5 business days
- **Fix timeline** — critical issues: 7 days, high: 14 days, medium: 30 days
- **Disclosure** — coordinated disclosure with reporter's preferred timeline

## Cryptographic Considerations

This is a cryptographic project. If you discover:
- Timing side channels in PQ algorithm implementations
- Weaknesses in the hybrid combiner (X25519MLKEM768)
- Issues in session management or key material handling
- Flaws in the crypto-agility policy engine

Please report them immediately.

## Recognition

We maintain a security hall of fame (HALL_OF_FAME.md) for researchers who responsibly disclose vulnerabilities. You can choose to be credited or remain anonymous.

## GPG Key (Optional)

For encrypted communication, use the following GPG key (add your actual key here when ready):

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
[YOUR KEY HERE]
-----END PGP PUBLIC KEY BLOCK-----
```
