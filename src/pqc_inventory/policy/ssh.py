"""Grade an SSH inventory against the `ssh` section of rules.yaml.

Priorities mirror the TLS grader: broken (P1), weak (P2), quantum-vulnerable key exchange
(P3), quantum-vulnerable host keys (P4), quantum-ready (P5).
"""

from __future__ import annotations

from typing import Any

from pqc_inventory.models import SshScanResult
from pqc_inventory.policy import load_rules
from pqc_inventory.policy.engine import (
    BROKEN,
    QV,
    READY,
    WEAK,
    Finding,
    GradeReport,
    _deadline_text,
    build_report,
    ifc_ffc_strength,
    nist_timeline,
)

CERT_SUFFIX = "-cert-v01@openssh.com"


def grade_ssh_kex(scan: SshScanResult, rules: dict[str, Any]) -> list[Finding]:
    kx, sev = rules["ssh"]["kex"], rules["severity"]
    algorithms = [a for a in scan.kex if a not in kx["pseudo"]]
    pq_offered = any(a in kx["quantum_ready"] for a in algorithms)

    findings = []
    for alg in algorithms:
        if alg in kx["quantum_ready"]:
            findings.append(
                Finding(
                    "key_exchange",
                    alg,
                    READY,
                    sev[READY],
                    5,
                    "Hybrid post-quantum key exchange is offered.",
                )
            )
        elif alg in kx["broken"]:
            findings.append(
                Finding(
                    "key_exchange",
                    alg,
                    BROKEN,
                    sev[BROKEN],
                    1,
                    "SHA-1 based or undersized key exchange; disable it.",
                )
            )
        else:
            strength = kx["strength"].get(alg)
            timeline = nist_timeline(strength, rules)
            known = "" if strength else " (unrecognized algorithm; strength unknown)"
            if pq_offered:
                findings.append(
                    Finding(
                        "key_exchange",
                        alg,
                        QV,
                        sev["classical_fallback_key_exchange"],
                        3,
                        "Classical fallback for clients without post-quantum support"
                        f"{known}. NIST IR 8547: {_deadline_text(timeline)}.",
                        timeline,
                    )
                )
            else:
                findings.append(
                    Finding(
                        "key_exchange",
                        alg,
                        QV,
                        sev["quantum_vulnerable_key_exchange"],
                        3,
                        "Classical key exchange: recorded sessions can be decrypted later"
                        f"{known}. NIST IR 8547: {_deadline_text(timeline)}.",
                        timeline,
                    )
                )
    return findings


def _host_key_strength(alg: str, scan: SshScanResult) -> int | None:
    base = alg.removesuffix(CERT_SUFFIX).removeprefix("sk-")
    if base.startswith("rsa-sha2-") or base == "ssh-rsa":
        rsa = [k.key for k in scan.host_keys if k.key.algorithm == "RSA" and k.key.size_bits]
        return ifc_ffc_strength(rsa[0].size_bits) if rsa else 112  # assume 2048 if unknown
    if base.startswith("ecdsa-sha2-nistp"):
        return min(int(base.removeprefix("ecdsa-sha2-nistp").split("@")[0]) // 2, 256)
    if base.startswith("ssh-ed25519"):
        return 128
    if base.startswith("ssh-ed448"):
        return 224
    return None


def grade_ssh_host_keys(scan: SshScanResult, rules: dict[str, Any]) -> list[Finding]:
    hk, sev = rules["ssh"]["host_key_algorithms"], rules["severity"]
    findings = []
    for alg in scan.host_key_algorithms:
        base = alg.removesuffix(CERT_SUFFIX)
        if base in hk["broken"]:
            findings.append(
                Finding("host_key", alg, BROKEN, sev[BROKEN], 1, f"{hk['broken'][base]}.")
            )
            continue
        timeline = nist_timeline(_host_key_strength(alg, scan), rules)
        findings.append(
            Finding(
                "host_key",
                alg,
                QV,
                sev["quantum_vulnerable_certificate"],
                4,
                f"Classical host key signature. NIST IR 8547: {_deadline_text(timeline)}.",
                timeline,
            )
        )
    for hkey in scan.host_keys:
        if hkey.key.algorithm == "RSA" and (hkey.key.size_bits or 0) < hk["rsa_min_bits"]:
            findings.append(
                Finding(
                    "host_key",
                    f"RSA-{hkey.key.size_bits} host key",
                    BROKEN,
                    sev[BROKEN],
                    1,
                    f"RSA host key below {hk['rsa_min_bits']} bits.",
                )
            )
    return findings


def grade_ssh_symmetric(scan: SshScanResult, rules: dict[str, Any]) -> list[Finding]:
    ssh, sev = rules["ssh"], rules["severity"]
    findings = []
    for cipher in scan.ciphers:
        if cipher in ssh["ciphers"]["broken"]:
            findings.append(
                Finding("cipher", cipher, BROKEN, sev[BROKEN], 1, "Broken or null cipher.")
            )
        elif cipher.endswith(ssh["ciphers"]["weak_suffix"]):
            findings.append(
                Finding(
                    "cipher",
                    cipher,
                    WEAK,
                    sev[WEAK],
                    2,
                    "CBC mode; prefer AES-GCM, AES-CTR, or ChaCha20-Poly1305.",
                )
            )
    for mac in scan.macs:
        if any(tok in mac for tok in ssh["macs"]["broken_if_contains"]):
            findings.append(
                Finding("mac", mac, BROKEN, sev[BROKEN], 1, "MD5, truncated, or null MAC.")
            )
        elif mac in ssh["macs"]["weak"]:
            findings.append(
                Finding(
                    "mac",
                    mac,
                    WEAK,
                    sev[WEAK],
                    2,
                    "SHA-1 or 64-bit tag MAC; prefer HMAC-SHA2 with encrypt-then-MAC.",
                )
            )
    return findings


def grade_terrapin(scan: SshScanResult, rules: dict[str, Any]) -> list[Finding]:
    t, sev = rules["ssh"]["terrapin"], rules["severity"]
    if t["strict_marker"] in scan.kex:
        return []
    chacha = any(c in t["vulnerable_ciphers"] for c in scan.ciphers)
    cbc_etm = any(c.endswith("-cbc") for c in scan.ciphers) and any(
        m.endswith("-etm@openssh.com") for m in scan.macs
    )
    if not (chacha or cbc_etm):
        return []
    return [
        Finding(
            "protocol",
            "Terrapin (CVE-2023-48795)",
            WEAK,
            sev[WEAK],
            2,
            "Server offers ChaCha20-Poly1305 or CBC with encrypt-then-MAC but not strict key "
            "exchange; a man-in-the-middle can truncate handshake messages. Upgrade OpenSSH "
            "to 9.6+ or disable the affected modes.",
        )
    ]


def grade_ssh(scan: SshScanResult, rules: dict[str, Any] | None = None) -> GradeReport:
    rules = rules or load_rules()
    findings = (
        grade_ssh_kex(scan, rules)
        + grade_ssh_host_keys(scan, rules)
        + grade_ssh_symmetric(scan, rules)
        + grade_terrapin(scan, rules)
    )
    return build_report(findings, None)
