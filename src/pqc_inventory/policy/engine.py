"""Grade a TLS inventory against rules.yaml.

Produces findings sorted by migration priority:
  1. broken today              (fix now, regardless of quantum)
  2. weak today                (fix soon)
  3. quantum-vulnerable key exchange  (harvest-now-decrypt-later exposure)
  4. quantum-vulnerable certificates  (forgery only matters once a quantum computer exists)
  5. quantum-ready             (informational)
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from pqc_inventory.models import CertificateInfo, KeyExchangeInfo, TlsScanResult
from pqc_inventory.policy import load_rules

BROKEN, WEAK, QV, READY = "broken", "weak", "quantum_vulnerable", "quantum_ready"
STATUS_ORDER = [BROKEN, WEAK, QV, READY]


@dataclass
class NistTimeline:
    security_strength_bits: int | None
    deprecated_after: int | None
    disallowed_after: int | None


@dataclass
class Finding:
    category: str  # protocol | cipher_suite | key_exchange | certificate | signature_hash
    subject: str
    status: str
    severity: str
    priority: int
    detail: str
    nist: NistTimeline | None = None


@dataclass
class GradeReport:
    verdict: str
    hndl_exposed: bool
    earliest_deadline: int | None
    counts: dict[str, int]
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --- security strength (NIST SP 800-57 Part 1 Rev. 5, Table 2) -------------------------


def ifc_ffc_strength(bits: int) -> int:
    """Security strength of RSA or finite-field DH for a given modulus size."""
    for threshold, strength in ((15360, 256), (7680, 192), (3072, 128), (2048, 112), (1024, 80)):
        if bits >= threshold:
            return strength
    return 0


def certificate_strength(cert: CertificateInfo) -> int | None:
    key = cert.public_key
    if key.algorithm in ("RSA", "DSA") and key.size_bits:
        return ifc_ffc_strength(key.size_bits)
    if key.algorithm == "EC" and key.size_bits:
        return min(key.size_bits // 2, 256)
    return {"Ed25519": 128, "Ed448": 224}.get(key.algorithm)


def nist_timeline(strength: int | None, rules: dict[str, Any]) -> NistTimeline:
    for tier in rules["nist_ir_8547"]["timeline"]:
        if strength is None or strength <= tier["max_strength"]:
            return NistTimeline(
                strength, tier.get("deprecated_after"), tier.get("disallowed_after")
            )
    last = rules["nist_ir_8547"]["timeline"][-1]
    return NistTimeline(strength, last.get("deprecated_after"), last.get("disallowed_after"))


def _deadline_text(t: NistTimeline) -> str:
    if t.deprecated_after:
        return f"deprecated after {t.deprecated_after}, disallowed after {t.disallowed_after}"
    return f"disallowed after {t.disallowed_after}"


# --- individual checks ----------------------------------------------------------------


def grade_protocols(scan: TlsScanResult, rules: dict[str, Any]) -> list[Finding]:
    findings = []
    for name, info in scan.protocols.items():
        rule = rules["protocols"].get(name)
        if info.supported and rule:
            findings.append(
                Finding(
                    "protocol",
                    name,
                    rule["status"],
                    rule["severity"],
                    1,
                    f"{name} is enabled; disable it and require TLS 1.2 or later.",
                )
            )
    return findings


def grade_cipher_suites(scan: TlsScanResult, rules: dict[str, Any]) -> list[Finding]:
    cs_rules, sev = rules["cipher_suites"], rules["severity"]
    seen: set[str] = set()
    findings = []
    for proto in scan.protocols.values():
        for suite in proto.cipher_suites:
            if suite.name in seen:
                continue
            seen.add(suite.name)
            if any(tok in suite.name for tok in cs_rules["broken_if_name_contains"]):
                findings.append(
                    Finding(
                        "cipher_suite",
                        suite.name,
                        BROKEN,
                        sev[BROKEN],
                        1,
                        "Cipher suite uses a broken or null primitive.",
                    )
                )
            elif suite.name.startswith(cs_rules["static_rsa_prefix"]):
                findings.append(
                    Finding(
                        "cipher_suite",
                        suite.name,
                        BROKEN,
                        sev[BROKEN],
                        1,
                        "Static RSA key transport provides no forward secrecy.",
                    )
                )
            elif any(tok in suite.name for tok in cs_rules["weak_if_name_contains"]):
                findings.append(
                    Finding(
                        "cipher_suite",
                        suite.name,
                        WEAK,
                        sev[WEAK],
                        2,
                        "CBC-mode suite; prefer AEAD (GCM or ChaCha20-Poly1305).",
                    )
                )
    return findings


def _group_name(kex: KeyExchangeInfo) -> str:
    if kex.curve:
        return kex.curve.lower()
    if kex.type.upper() == "DH":
        return f"dh-{kex.size_bits}"
    return kex.type.lower()


def grade_key_exchange(scan: TlsScanResult, rules: dict[str, Any]) -> list[Finding]:
    kx, sev = rules["key_exchange"], rules["severity"]
    groups: dict[str, int | None] = {}  # normalized name -> DH size (if DH)

    for proto in scan.protocols.values():
        for suite in proto.cipher_suites:
            if suite.key_exchange:
                groups[_group_name(suite.key_exchange)] = suite.key_exchange.size_bits
    for g in scan.supported_groups:
        groups.setdefault(g.lower(), None)

    findings = []
    for raw_name, size in sorted(groups.items()):
        name = kx["aliases"].get(raw_name, raw_name)
        if name in kx["quantum_ready"]:
            findings.append(
                Finding(
                    "key_exchange",
                    name,
                    READY,
                    sev[READY],
                    5,
                    "Hybrid or pure post-quantum key exchange is offered.",
                )
            )
            continue
        if name.startswith("dh-"):
            strength = ifc_ffc_strength(size or 0)
            if (size or 0) < kx["dh_min_bits"]:
                findings.append(
                    Finding(
                        "key_exchange",
                        name,
                        BROKEN,
                        sev[BROKEN],
                        1,
                        f"Finite-field DH below {kx['dh_min_bits']} bits.",
                        NistTimeline(strength, None, None),
                    )
                )
                continue
        else:
            strength = kx["group_strength"].get(name)
            if strength is not None and strength < 112:
                findings.append(
                    Finding(
                        "key_exchange",
                        name,
                        BROKEN,
                        sev[BROKEN],
                        1,
                        "Group provides less than 112-bit classical security.",
                    )
                )
                continue
        timeline = nist_timeline(strength, rules)
        findings.append(
            Finding(
                "key_exchange",
                name,
                QV,
                sev["quantum_vulnerable_key_exchange"],
                3,
                "Classical key exchange: traffic recorded today can be decrypted later "
                f"(harvest now, decrypt later). NIST IR 8547: {_deadline_text(timeline)}.",
                timeline,
            )
        )
    return findings


def _position(index: int, cert: CertificateInfo) -> str:
    if index == 0:
        return "leaf"
    return "root" if cert.subject == cert.issuer else "intermediate"


def grade_certificates(scan: TlsScanResult, rules: dict[str, Any]) -> list[Finding]:
    ck, sev = rules["certificate_keys"], rules["severity"]
    findings = []
    chain = scan.certificate_chain
    for i, cert in enumerate(chain):
        pos = _position(i, cert)
        key = cert.public_key
        label = f"{pos}: {key.algorithm}" + (f"-{key.size_bits}" if key.size_bits else "")
        label += f" ({key.curve})" if key.curve else ""

        if cert.signature_hash and cert.signature_hash in rules["signature_hashes"]["broken"]:
            if pos != "root":  # a root's self-signature is not relied on for trust
                findings.append(
                    Finding(
                        "signature_hash",
                        f"{pos}: {cert.signature_hash}",
                        BROKEN,
                        sev[BROKEN],
                        1,
                        f"{cert.subject} is signed with a broken hash.",
                    )
                )

        if key.algorithm.lower() in ck["quantum_ready"]:
            findings.append(
                Finding(
                    "certificate", label, READY, sev[READY], 5, "Post-quantum signature algorithm."
                )
            )
            continue
        if key.algorithm == "RSA" and (key.size_bits or 0) < ck["rsa_min_bits"]:
            findings.append(
                Finding(
                    "certificate",
                    label,
                    BROKEN,
                    sev[BROKEN],
                    1,
                    f"RSA key below {ck['rsa_min_bits']} bits.",
                )
            )
            continue
        timeline = nist_timeline(certificate_strength(cert), rules)
        findings.append(
            Finding(
                "certificate",
                label,
                QV,
                sev["quantum_vulnerable_certificate"],
                4,
                f"Classical signature key. NIST IR 8547: {_deadline_text(timeline)}.",
                timeline,
            )
        )
    return findings


# --- entry point ----------------------------------------------------------------------


def grade(scan: TlsScanResult, rules: dict[str, Any] | None = None) -> GradeReport:
    rules = rules or load_rules()
    findings = (
        grade_protocols(scan, rules)
        + grade_cipher_suites(scan, rules)
        + grade_key_exchange(scan, rules)
        + grade_certificates(scan, rules)
    )
    findings.sort(key=lambda f: (f.priority, f.category, f.subject))

    counts = {s: sum(f.status == s for f in findings) for s in STATUS_ORDER}
    present = [s for s in STATUS_ORDER if counts[s]]
    verdict = present[0] if present else "unknown"

    kex = [f for f in findings if f.category == "key_exchange"]
    hndl_exposed = any(f.status in (QV, BROKEN) for f in kex)

    deadlines = [
        f.nist.deprecated_after or f.nist.disallowed_after
        for f in findings
        if f.nist and (f.nist.deprecated_after or f.nist.disallowed_after)
    ]
    return GradeReport(
        verdict, hndl_exposed, min(deadlines) if deadlines else None, counts, findings
    )
