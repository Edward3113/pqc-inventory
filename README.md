# pqc-inventory

![CI](https://github.com/Edward3113/pqc-inventory/actions/workflows/ci.yml/badge.svg)

**pqc-inventory** scans TLS and SSH endpoints, records every algorithm they offer, and
grades each one against NIST's post-quantum transition timeline (NIST IR 8547). It
detects hybrid post-quantum key exchange such as X25519MLKEM768, flags endpoints exposed
to "harvest now, decrypt later", and turns the results into a prioritized migration plan,
a CycloneDX 1.6 cryptographic bill of materials (CBOM), and a self-contained HTML report.

**[View the live demo report](https://edward3113.github.io/pqc-inventory/)** and its
[CycloneDX CBOM](https://edward3113.github.io/pqc-inventory/cbom.json). CI rebuilds both on
every push by scanning a lab of five deliberately configured servers.

## Why

Most TLS and SSH traffic today relies on RSA and elliptic-curve cryptography, which a
cryptographically relevant quantum computer could break. NIST has proposed deprecating
these algorithms after 2030 and disallowing them after 2035. Traffic recorded today can
be decrypted later ("harvest now, decrypt later"), so organizations need to know where
quantum-vulnerable key exchange lives on their networks now. You can't migrate what you
haven't inventoried.

## Companion project

pqc-inventory is the first project in a series. A later one,
[btc_trace](https://github.com/Edward3113/btc_trace), traces Bitcoin from
OFAC-sanctioned addresses using a self-hosted node. Its planned Phase 2 asks the
question this tool asks of networks, where quantum-vulnerable cryptography is exposed
on the Bitcoin blockchain, and how much BTC sits in outputs whose public keys are already
visible on-chain. The two tools share no code, and each works on its own.

## Authorized use

Only scan systems you own or have written permission to test.

## Try the demo lab

Requires Docker (Docker Desktop or OrbStack). Nothing else needs to be installed; the
scanner runs in a container with OpenSSL 3.5.

```bash
docker compose -f lab/compose.yaml up -d --build --wait
docker compose -f lab/compose.yaml run --rm scanner
open lab/output/index.html
docker compose -f lab/compose.yaml down
```

| Target | Configuration | Expected verdict |
|---|---|---|
| `tls-legacy` | TLS 1.0–1.2, RSA-1024 certificate signed with SHA-1, static RSA | Broken |
| `tls-classical` | TLS 1.2/1.3, AEAD only, ECDSA P-256, classical key exchange | Quantum-vulnerable, HNDL exposed |
| `tls-pq` | Same, plus hybrid X25519MLKEM768 | Quantum-vulnerable, PQ key exchange |
| `ssh-legacy` | SHA-1 key exchange, `ssh-rsa` signatures, CBC | Broken |
| `ssh-modern` | Stock OpenSSH 10 (ML-KEM hybrid by default) | Weak (default MACs), PQ key exchange |

The targets are also published on localhost (ports 8441–8443, 2221–2222), so a local
install can scan them too. These servers are deliberately misconfigured; never reuse
their settings.

## Quick start

```bash
uv sync
uv run pqc-inventory example.com -f text                # human-readable graded report
uv run pqc-inventory 192.168.1.10:8443 -o reports/host.json   # full JSON (scan + grade)
uv run pqc-inventory example.com --fail-on broken       # exit code 2 if anything is broken
uv run pqc-inventory example.com --no-pq-probe          # skip the post-quantum probe
uv run pqc-inventory -p ssh 192.168.1.20 -f text        # SSH (default port 22)
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
...
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

## Examples

### Stock OpenSSH 9.6

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

### Local TLS server with hybrid PQ enabled

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

### github.com (September 2026)

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

## Related work

This project is a learning and portfolio project in an active field. If you need a
cryptographic inventory tool, evaluate these as well:

- **[sslyze](https://github.com/nabla-c0d3/sslyze)**, **[testssl.sh](https://testssl.sh)**,
  and **[ssh-audit](https://github.com/jtesta/ssh-audit)**: the established TLS and SSH
  configuration scanners. pqc-inventory uses sslyze for its TLS handshakes.
- **[AC Scanner](https://github.com/qubitac/AC-Scanner)**: a TLS and SSH post-quantum
  scanner with subdomain discovery, hybrid key exchange detection, CBOM output mapped to
  NIST IR 8547, and a hosted dashboard.
- **[Open Quantum Secure](https://github.com/jimbo111/open-quantum-secure)**: scans source
  code across many languages as well as live TLS and SSH endpoints, with CycloneDX 1.7
  output, a readiness score, and checks against multiple compliance frameworks.
- **[CBOM-Lens](https://github.com/OmniTrustILM/cbom-lens)**: builds CBOMs from
  filesystems, container images, and network ports, with detailed modeling of
  post-quantum algorithms.
- **[CBOMkit](https://github.com/IBM/cbomkit)** (IBM) and similar tools generate CBOMs
  from source code rather than from network traffic.
- Commercial platforms such as IBM Quantum Safe, SandboxAQ AQtive Guard, and O3 Security
  cover discovery and migration planning at enterprise scale.

### This project's focus

- **Deadlines tied to security strength.** Each algorithm's classical strength is
  computed per NIST SP 800-57, so RSA-2048 and DH-2048 land on the 2030 deprecation date
  while P-256, X25519, and RSA-3072 land on the 2035 disallowance date.
- **Harvest-now-decrypt-later prioritization.** Key exchange ranks above signatures, and
  a classical group offered alongside ML-KEM is graded as a low-severity fallback rather
  than as exposure.
- **Treating scanned servers as untrusted input.** The SSH parser is tested against
  hostile servers, OpenSSL is invoked without a shell and with validated hostnames, and
  the HTML report escapes all server-supplied text under a script-blocking
  Content-Security-Policy.
- **Verifiable output.** The CBOM is validated against the official CycloneDX 1.6 schema
  in CI, and a Docker lab of five servers reproduces every verdict the tool can produce.

## Roadmap

- [x] 1. TLS inventory for a single host
- [x] 2. Policy engine: grade findings as broken / weak / quantum-vulnerable / quantum-ready
- [x] 3. Hybrid post-quantum key exchange probe (X25519MLKEM768 via OpenSSL 3.5+)
- [x] 4. SSH scanning (key exchange, host keys, ciphers, MACs, Terrapin)
- [x] 5. CIDR range scanning with discovery, protocol auto-detection, and concurrency
- [x] 6. CycloneDX 1.6 CBOM + HTML report with prioritized migration list
- [x] 7. Docker demo lab, full test suite in CI on OpenSSL 3.5, GitHub Pages demo report

## Development

```bash
uv sync --group dev
uv run ruff check .
uv run ruff format --check .
uv run pytest
```

The live post-quantum tests need OpenSSL 3.5+, and the live SSH test needs an sshd on
127.0.0.1:2222; each is skipped when unavailable. CI runs the full suite on Debian 13,
which ships OpenSSL 3.5, with a local sshd.

## Acknowledgments

pqc-inventory is a thin layer over a lot of other people's work.

- **[SSLyze](https://github.com/nabla-c0d3/sslyze)** and **nassl** by Alban Diquet, which
  perform every TLS handshake in this tool.
- **[OpenSSL](https://www.openssl.org)**, whose 3.5 release brought ML-KEM hybrid key
  exchange that the post-quantum probe relies on, and **[OpenSSH](https://www.openssh.com)**,
  which made hybrid post-quantum key exchange the default for SSH.
- **[pyca/cryptography](https://cryptography.io)** for certificate and key parsing.
- **[CycloneDX](https://cyclonedx.org)** (OWASP) for the CBOM specification, and
  **cyclonedx-python-lib**, whose bundled schemas validate this tool's output in CI.
- **Jinja2**, **PyYAML**, **pytest**, and Astral's **uv** and **ruff**.
- **NIST** for IR 8547 (Moody, Perlner, Regenscheid, Robinson, and Cooper), SP 800-57,
  and FIPS 203, which define the deadlines and security strengths used for grading.
- **Fabian Bäumer, Marcus Brinkmann, and Jörg Schwenk** (Ruhr University Bochum) for the
  [Terrapin attack](https://terrapin-attack.com) research (CVE-2023-48795) behind the SSH
  Terrapin check.
- The projects listed under [Related work](#related-work), whose approaches informed
  this one.

Developed with assistance from Claude (Anthropic).

## License

AGPL-3.0-only; see [LICENSE](LICENSE). pqc-inventory is built on SSLyze and nassl, which
are licensed under the AGPL-3.0.
