# pqc-inventory

A scanner that builds a cryptographic inventory of network endpoints and grades each
algorithm against NIST's post-quantum transition timeline (NIST IR 8547).

> **Status:** Milestone 1 of 7 — single-host TLS inventory. Grading, SSH, hybrid PQ
> detection, CycloneDX CBOM output, and the lab/report pipeline are on the roadmap below.

## Why

Most TLS and SSH traffic today relies on RSA and elliptic-curve cryptography, which a
cryptographically relevant quantum computer could break. NIST has proposed deprecating
these algorithms after 2030 and disallowing them after 2035. Traffic recorded today can
be decrypted later ("harvest now, decrypt later"), so organizations need to know where
quantum-vulnerable key exchange lives on their networks now. You can't migrate what you
haven't inventoried.

## Quick start

```bash
uv sync
uv run pqc-inventory example.com
uv run pqc-inventory 192.168.1.10:8443 -o reports/host.json
```

Output is JSON listing supported protocol versions, accepted cipher suites with their
key exchange, supported groups, and the certificate chain's key and signature algorithms.

## Roadmap

- [x] 1. TLS inventory for a single host
- [ ] 2. Policy engine: grade findings as broken / quantum-vulnerable / quantum-ready
- [ ] 3. Hybrid post-quantum key exchange probe (X25519MLKEM768 via OpenSSL 3.5+)
- [ ] 4. SSH scanning
- [ ] 5. CIDR range scanning with concurrency
- [ ] 6. CycloneDX 1.6 CBOM + HTML report with prioritized migration list
- [ ] 7. Docker lab targets, CI scan, GitLab Pages demo report

Grading rules live in [`rules.yaml`](src/pqc_inventory/policy/rules.yaml), so policy
updates don't require code changes.

## Authorized use

Only scan systems you own or have written permission to test.

## License

MIT
