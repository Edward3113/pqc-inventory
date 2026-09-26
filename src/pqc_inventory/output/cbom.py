"""CycloneDX 1.6 cryptographic bill of materials (CBOM).

Structure:
  services      one per scanned endpoint (host:port), with its verdict
  components    cryptographic assets, de-duplicated across endpoints:
                  protocol     TLS 1.2 / TLS 1.3 / SSH 2.0 per endpoint
                  algorithm    key exchange, signatures, ciphers, MACs, public keys
                  certificate  each certificate in each chain
  dependencies  service -> protocol -> algorithms / certificates

Grading results ride along as component properties in the "pqc-inventory:" namespace, so
any CycloneDX consumer can read the inventory and ours can read the verdicts.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any

from pqc_inventory import __version__
from pqc_inventory.batch import EndpointResult
from pqc_inventory.models import SshScanResult, TlsScanResult
from pqc_inventory.policy.engine import READY, Finding

NS = "pqc-inventory"
AEAD_MARKERS = ("gcm", "chacha20-poly1305", "poly1305", "ccm")


def _slug(text: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "-", text).strip("-").lower()


def _nist_quantum_level(name: str, status: str | None) -> int | None:
    lowered = name.lower()
    if "mlkem1024" in lowered or "ml-dsa-87" in lowered:
        return 5
    if "mlkem768" in lowered or "ml-dsa-65" in lowered:
        return 3
    if "ml-dsa-44" in lowered:
        return 2
    if status == READY:
        return None  # non-NIST PQ (e.g. sntrup761): no NIST category to claim
    return 0  # classical: meets no NIST post-quantum category


class _Registry:
    def __init__(self) -> None:
        self.components: dict[str, dict[str, Any]] = {}

    def add(self, ref: str, component: dict[str, Any]) -> str:
        if ref not in self.components:
            component["bom-ref"] = ref
            self.components[ref] = component
        else:
            _merge_properties(self.components[ref], component.get("properties", []))
        return ref

    def algorithm(
        self,
        name: str,
        primitive: str,
        finding: Finding | None = None,
        *,
        functions: list[str] | None = None,
        mode: str | None = None,
        curve: str | None = None,
        classical: int | None = None,
    ) -> str:
        status = finding.status if finding else "ok"
        algo: dict[str, Any] = {"primitive": primitive}
        if curve:
            algo["curve"] = curve
        if mode:
            algo["mode"] = mode
        if functions:
            algo["cryptoFunctions"] = functions
        strength = classical or (
            finding.nist.security_strength_bits if finding and finding.nist else None
        )
        if strength:
            algo["classicalSecurityLevel"] = strength
        level = _nist_quantum_level(name, status)
        if level is not None and primitive in ("kem", "key-agree", "signature"):
            algo["nistQuantumSecurityLevel"] = level
        return self.add(
            f"crypto/algorithm/{_slug(name)}",
            {
                "type": "cryptographic-asset",
                "name": name,
                "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": algo},
                "properties": _finding_properties(finding, status),
            },
        )


def _finding_properties(finding: Finding | None, status: str) -> list[dict[str, str]]:
    props = [{"name": f"{NS}:status", "value": status}]
    if finding:
        props.append({"name": f"{NS}:priority", "value": f"P{finding.priority}"})
        if finding.nist and finding.nist.deprecated_after:
            props.append(
                {
                    "name": f"{NS}:nist-ir-8547:deprecated-after",
                    "value": str(finding.nist.deprecated_after),
                }
            )
        if finding.nist and finding.nist.disallowed_after:
            props.append(
                {
                    "name": f"{NS}:nist-ir-8547:disallowed-after",
                    "value": str(finding.nist.disallowed_after),
                }
            )
    return props


def _merge_properties(component: dict[str, Any], new: list[dict[str, str]]) -> None:
    existing = {(p["name"], p["value"]) for p in component.setdefault("properties", [])}
    for prop in new:
        if (prop["name"], prop["value"]) not in existing:
            component["properties"].append(prop)


def _index(result: EndpointResult) -> dict[tuple[str, str], Finding]:
    if not result.grade:
        return {}
    return {(f.category, f.subject): f for f in result.grade.findings}


# --- TLS --------------------------------------------------------------------------------


def _tls_components(reg: _Registry, r: EndpointResult, scan: TlsScanResult) -> list[str]:
    found = _index(r)
    refs: list[str] = []

    kex_refs = []
    for (category, subject), finding in found.items():
        if category == "key_exchange":
            primitive = "kem" if finding.status == READY else "key-agree"
            functions = ["encapsulate", "decapsulate"] if primitive == "kem" else ["keyderive"]
            kex_refs.append(reg.algorithm(subject, primitive, finding, functions=functions))

    cert_refs = []
    chain = scan.certificate_chain
    for i, cert in enumerate(chain):
        pos = "leaf" if i == 0 else ("root" if cert.subject == cert.issuer else "intermediate")
        key = cert.public_key
        key_label = f"{key.algorithm}-{key.size_bits}" if key.size_bits else key.algorithm
        finding = next(
            (f for (c, s), f in found.items() if c == "certificate" and s.startswith(f"{pos}: ")),
            None,
        )
        key_ref = reg.algorithm(
            key_label + (f" ({key.curve})" if key.curve else ""),
            "signature",
            finding,
            functions=["sign", "verify"],
            curve=key.curve,
        )
        sig_finding = found.get(("signature_hash", f"{pos}: {cert.signature_hash}"))
        sig_ref = reg.algorithm(
            cert.signature_algorithm, "signature", sig_finding, functions=["verify"]
        )
        cert_refs.append(
            reg.add(
                f"crypto/certificate/{_slug(cert.subject)}/{_slug(cert.not_after)}",
                {
                    "type": "cryptographic-asset",
                    "name": cert.subject,
                    "cryptoProperties": {
                        "assetType": "certificate",
                        "certificateProperties": {
                            "subjectName": cert.subject,
                            "issuerName": cert.issuer,
                            "notValidBefore": cert.not_before,
                            "notValidAfter": cert.not_after,
                            "signatureAlgorithmRef": sig_ref,
                            "subjectPublicKeyRef": key_ref,
                            "certificateFormat": "X.509",
                        },
                    },
                    "properties": [{"name": f"{NS}:chain-position", "value": pos}],
                },
            )
        )

    for version, info in scan.protocols.items():
        if not info.supported:
            continue
        proto_finding = found.get(("protocol", version))
        props = _finding_properties(proto_finding, proto_finding.status if proto_finding else "ok")
        suites = []
        for suite in info.cipher_suites:
            suite_finding = found.get(("cipher_suite", suite.name))
            suites.append({"name": suite.name})
            if suite_finding:
                props.append(
                    {"name": f"{NS}:cipher-suite:{suite.name}", "value": suite_finding.status}
                )
        family, _, number = version.partition(" ")
        refs.append(
            reg.add(
                f"crypto/protocol/{_slug(r.host)}-{r.port}/{_slug(version)}",
                {
                    "type": "cryptographic-asset",
                    "name": version,
                    "cryptoProperties": {
                        "assetType": "protocol",
                        "protocolProperties": {
                            "type": "tls" if family == "TLS" else "other",
                            "version": number,
                            "cipherSuites": suites,
                            "cryptoRefArray": kex_refs + cert_refs,
                        },
                    },
                    "properties": props,
                },
            )
        )
    return refs


# --- SSH --------------------------------------------------------------------------------


def _cipher_shape(name: str) -> tuple[str, str | None]:
    lowered = name.lower()
    if any(m in lowered for m in AEAD_MARKERS):
        return "ae", "gcm" if "gcm" in lowered else None
    for mode in ("ctr", "cbc"):
        if lowered.endswith(f"-{mode}"):
            return "block-cipher", mode
    return "other", None


def _ssh_components(reg: _Registry, r: EndpointResult, scan: SshScanResult) -> list[str]:
    found = _index(r)
    crypto_refs = []
    for alg in scan.kex:
        finding = found.get(("key_exchange", alg))
        if finding is None:
            continue  # pseudo-algorithms such as ext-info-s / kex-strict markers
        primitive = "kem" if finding.status == READY else "key-agree"
        crypto_refs.append(reg.algorithm(alg, primitive, finding))
    for alg in scan.host_key_algorithms:
        crypto_refs.append(
            reg.algorithm(
                alg, "signature", found.get(("host_key", alg)), functions=["sign", "verify"]
            )
        )
    for cipher in scan.ciphers:
        primitive, mode = _cipher_shape(cipher)
        crypto_refs.append(
            reg.algorithm(
                cipher,
                primitive,
                found.get(("cipher", cipher)),
                mode=mode,
                functions=["encrypt", "decrypt"],
            )
        )
    for mac in scan.macs:
        crypto_refs.append(reg.algorithm(mac, "mac", found.get(("mac", mac)), functions=["tag"]))

    terrapin = found.get(("protocol", "Terrapin (CVE-2023-48795)"))
    props = [{"name": f"{NS}:banner", "value": scan.banner or ""}]
    if terrapin:
        props.append({"name": f"{NS}:terrapin", "value": "vulnerable"})
    return [
        reg.add(
            f"crypto/protocol/{_slug(r.host)}-{r.port}/ssh-2.0",
            {
                "type": "cryptographic-asset",
                "name": "SSH 2.0",
                "cryptoProperties": {
                    "assetType": "protocol",
                    "protocolProperties": {
                        "type": "ssh",
                        "version": "2.0",
                        "cryptoRefArray": crypto_refs,
                    },
                },
                "properties": props,
            },
        )
    ]


# --- document ---------------------------------------------------------------------------


def build_cbom(results: list[EndpointResult]) -> dict[str, Any]:
    reg = _Registry()
    services, dependencies = [], []

    for r in results:
        if r.grade is None:
            continue
        if isinstance(r.scan, SshScanResult):
            proto_refs = _ssh_components(reg, r, r.scan)
            scheme = "ssh"
        else:
            proto_refs = _tls_components(reg, r, r.scan)
            scheme = "https" if r.port == 443 else "tls"
        service_ref = f"service/{_slug(r.host)}-{r.port}"
        services.append(
            {
                "bom-ref": service_ref,
                "name": f"{r.host}:{r.port}",
                "endpoints": [f"{scheme}://{r.host}:{r.port}"],
                "properties": [
                    {"name": f"{NS}:verdict", "value": r.grade.verdict},
                    {
                        "name": f"{NS}:pq-key-exchange",
                        "value": str(r.grade.pq_key_exchange).lower(),
                    },
                    {"name": f"{NS}:hndl-exposed", "value": str(r.grade.hndl_exposed).lower()},
                ],
            }
        )
        dependencies.append({"ref": service_ref, "dependsOn": proto_refs})
        for ref in proto_refs:
            refs = reg.components[ref]["cryptoProperties"]["protocolProperties"].get(
                "cryptoRefArray", []
            )
            dependencies.append({"ref": ref, "dependsOn": list(dict.fromkeys(refs))})

    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
            "tools": {
                "components": [
                    {"type": "application", "name": "pqc-inventory", "version": __version__}
                ]
            },
        },
        "components": list(reg.components.values()),
        "services": services,
        "dependencies": dependencies,
    }
