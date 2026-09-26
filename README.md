# pqc-inventory

![CI](https://github.com/Edward3113/pqc-inventory/actions/workflows/ci.yml/badge.svg)

A scanner that builds a cryptographic inventory of network endpoints and grades each
algorithm against NIST's post-quantum transition timeline (NIST IR 8547).

> **Status:** Milestone 3 of 7 — single-host TLS inventory, policy grading, and hybrid
> post-quantum key exchange detection. SSH, range scanning, CycloneDX CBOM output, and the
> lab/report pipeline are on the roadmap below.

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
uv run pqc-inventory example.com -f text                # human-readable graded report
uv run pqc-inventory 192.168.1.10:8443 -o reports/host.json   # full JSON (scan + grade)
uv run pqc-inventory example.com --fail-on broken       # exit code 2 if anything is broken
uv run pqc-inventory example.com --no-pq-probe          # skip the post-quantum probe
```

### Post-quantum detection requires OpenSSL 3.5+

The tool's TLS library can't offer ML-KEM, so the post-quantum probe shells out to an
OpenSSL 3.5+ binary and offers each hybrid group (X25519MLKEM768, SecP256r1MLKEM768,
SecP384r1MLKEM1024) on its own. It looks for OpenSSL in this order: `--openssl PATH`, the
`PQC_OPENSSL` environment variable, Homebrew's `openssl@3`, then `openssl` on your PATH.
macOS's built-in `/usr/bin/openssl` is LibreSSL and is rejected automatically.

```bash
brew install openssl@3        # macOS
```

If no capable binary is found, the scan still runs and the report says the probe was
skipped. It never reports "no post-quantum support" when it simply couldn't check.

### Example: local server with hybrid PQ enabled

```
Verdict: QUANTUM-VULNERABLE
Post-quantum key exchange: YES
Harvest-now-decrypt-later exposure: no
Post-quantum probe: X25519MLKEM768 [OpenSSL 3.5.4]

[P3] QUANTUM-VULNERABLE  key_exchange    x25519
      Classical fallback for clients without post-quantum support; PQ-capable clients are protected.
[P4] QUANTUM-VULNERABLE  certificate     leaf: EC-256 (secp256r1)
[P5] QUANTUM-READY       key_exchange    x25519mlkem768
```

Key exchange is protected, but the certificate is still classical. That's today's
real-world state for PQ-enabled sites, since post-quantum certificates aren't yet
widely deployed in the public WebPKI.

### Example: github.com (September 2026)

```
Verdict: QUANTUM-VULNERABLE
Harvest-now-decrypt-later exposure: YES
Earliest NIST IR 8547 deadline: 2030
Findings — broken: 0, weak: 0, quantum-vulnerable: 5, quantum-ready: 0

[P3] QUANTUM-VULNERABLE  key_exchange    secp256r1
[P3] QUANTUM-VULNERABLE  key_exchange    x25519
[P4] QUANTUM-VULNERABLE  certificate     leaf: RSA-2048
...
```

A well-configured site with no classical weaknesses still grades as quantum-vulnerable:
every key exchange and signature is on NIST's retirement timeline.

## How grading works

Each finding gets a status and a migration priority:

| Priority | Status | Meaning |
|---|---|---|
| P1 | Broken | Weak today, regardless of quantum (TLS 1.0/1.1, RC4, static RSA, RSA < 2048, SHA-1 signatures) |
| P2 | Weak | Discouraged today (CBC-mode suites) |
| P3 | Quantum-vulnerable key exchange | Recorded traffic can be decrypted later: *harvest now, decrypt later* |
| P4 | Quantum-vulnerable certificate | Signatures can only be forged once a quantum computer exists |
| P5 | Quantum-ready | Hybrid or pure post-quantum (e.g. X25519MLKEM768, ML-DSA) |

Key exchange ranks above certificates because confidentiality loss is retroactive and
signature forgery is not.

NIST deadlines depend on classical security strength (NIST SP 800-57): 112-bit algorithms
such as RSA-2048 are deprecated after 2030 and disallowed after 2035, while 128-bit and
stronger algorithms such as P-256, X25519, and RSA-3072 are disallowed after 2035. IR 8547
is still a draft, so the dates live in [`rules.yaml`](src/pqc_inventory/policy/rules.yaml)
rather than in code.

## Roadmap

- [x] 1. TLS inventory for a single host
- [x] 2. Policy engine: grade findings as broken / weak / quantum-vulnerable / quantum-ready
- [x] 3. Hybrid post-quantum key exchange probe (X25519MLKEM768 via OpenSSL 3.5+)
- [ ] 4. SSH scanning
- [ ] 5. CIDR range scanning with concurrency
- [ ] 6. CycloneDX 1.6 CBOM + HTML report with prioritized migration list
- [ ] 7. Docker lab targets, CI scan, GitHub Pages demo report

## Authorized use

Only scan systems you own or have written permission to test.

## License

MIT
