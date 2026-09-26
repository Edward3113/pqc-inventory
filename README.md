# pqc-inventory

![CI](https://github.com/Edward3113/pqc-inventory/actions/workflows/ci.yml/badge.svg)

A scanner that builds a cryptographic inventory of network endpoints and grades each
algorithm against NIST's post-quantum transition timeline (NIST IR 8547).

> **Status:** Milestone 6 of 7 — TLS and SSH inventory across whole networks, policy
> grading, hybrid post-quantum detection, CycloneDX 1.6 CBOM output, and an HTML report.
> The demo lab and published sample report are next.

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
uv run pqc-inventory -p ssh 192.168.1.20 -f text        # SSH (default port 22)
```

### Reports: CBOM and HTML

```bash
uv run pqc-inventory 10.0.0.0/24 -f text --cbom reports/network.cbom.json --html reports/network.html
```

One scan produces all three outputs.

**CycloneDX 1.6 CBOM.** A cryptographic bill of materials in the OWASP CycloneDX
standard, so other security tools can import the inventory. Each endpoint is a service,
each protocol, algorithm, and certificate is a `cryptographic-asset` component with
`nistQuantumSecurityLevel` and `classicalSecurityLevel` set, and the grading results
travel as `pqc-inventory:` properties. Output is validated in CI against the official
CycloneDX 1.6 JSON schema.

**HTML report.** A single self-contained file for people who don't read JSON: a plain
English summary, a timeline showing how many findings land on the 2030 and 2035 NIST
deadlines, a migration plan that groups identical findings across endpoints so each fix
is made once, and expandable per-endpoint details. Because SSH banners and certificate
subjects come from servers that may be hostile, all content is HTML-escaped and the page
carries a Content-Security-Policy that forbids scripts entirely. It works in dark mode,
on phones, and in print.

### Scanning a network

```bash
uv run pqc-inventory 192.168.1.0/24 -f text                     # ports 22 and 443
uv run pqc-inventory 192.168.1.0/24 --ports 22,443,8443 -f text
uv run pqc-inventory -i targets.txt -o reports/network.json     # one target per line
```

A fast concurrent TCP sweep finds open ports first, so the cryptographic scans only run
against live endpoints. Each open port is classified automatically: SSH servers send
their banner immediately, while TLS servers wait for the client. Up to four endpoints
are scanned in parallel (`--workers`).

```
Endpoints: 8 checked, 5 open, 5 graded, 0 failed
Worst verdict: WEAK
Post-quantum key exchange: 3 of 5 endpoints
Harvest-now-decrypt-later exposure: 2 of 5 endpoints

ENDPOINT                 PROTO VERDICT             PQ KEX  HNDL  DETAIL
127.0.0.1:2222           ssh   WEAK                yes     no    SSH-2.0-OpenSSH_9.6p1
127.0.0.1:14433          tls   QUANTUM-VULNERABLE  yes     no
127.0.0.1:14434          tls   WEAK                no      YES
```

Safety rails: ranges outside private address space are refused unless you pass
`--allow-public`, and expansions over 1,024 hosts are refused unless you raise
`--max-hosts`. With `--fail-on`, the exit code reflects the worst endpoint.

### SSH scanning

SSH servers list every algorithm they support in their first key exchange message, before
any authentication. The scanner reads that message and disconnects, so it never sends
credentials. Host key sizes come from `ssh-keyscan`, which ships with macOS and Linux.

It grades key exchange (including OpenSSH's hybrid post-quantum `sntrup761x25519` and
`mlkem768x25519`), host key algorithms, ciphers, and MACs. It also checks for the
Terrapin attack (CVE-2023-48795): servers that offer ChaCha20-Poly1305 or CBC with
encrypt-then-MAC without strict key exchange are flagged.

Example against a stock OpenSSH 9.6 server:

```
Verdict: WEAK
Post-quantum key exchange: YES
Harvest-now-decrypt-later exposure: no
Server: SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.19

[P2] WEAK                mac             hmac-sha1
[P2] WEAK                mac             umac-64-etm@openssh.com
[P3] QUANTUM-VULNERABLE  key_exchange    curve25519-sha256   (classical fallback)
[P4] QUANTUM-VULNERABLE  host_key        ssh-ed25519
[P5] QUANTUM-READY       key_exchange    sntrup761x25519-sha512@openssh.com
```

OpenSSH is ahead of most of the web here: hybrid post-quantum key exchange has been
its default since version 9.0.

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
- [x] 4. SSH scanning (key exchange, host keys, ciphers, MACs, Terrapin)
- [x] 5. CIDR range scanning with discovery, protocol auto-detection, and concurrency
- [x] 6. CycloneDX 1.6 CBOM + HTML report with prioritized migration list
- [ ] 7. Docker lab targets, CI scan, GitHub Pages demo report

## Authorized use

Only scan systems you own or have written permission to test.

## License

MIT
