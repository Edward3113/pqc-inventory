"""Grading engine tests using synthetic scans — no network required."""

import pytest

from pqc_inventory.cli import main
from pqc_inventory.models import (
    CertificateInfo,
    CipherSuiteInfo,
    KeyExchangeInfo,
    ProtocolInfo,
    PublicKeyInfo,
    TlsScanResult,
)
from pqc_inventory.policy.engine import grade, ifc_ffc_strength


def cert(alg, bits, curve=None, hash_="sha256", subject="CN=leaf", issuer="CN=ca"):
    return CertificateInfo(
        subject,
        issuer,
        "2026-01-01",
        "2027-01-01",
        PublicKeyInfo(alg, bits, curve),
        "sig",
        hash_,
    )


def scan(protocols, groups=(), chain=()):
    return TlsScanResult(
        "test",
        443,
        "now",
        "completed",
        protocols=protocols,
        supported_groups=list(groups),
        certificate_chain=list(chain),
    )


def suite(name, kex_type="EC", curve="PRIME256V1", size=256):
    return CipherSuiteInfo(name, 128, KeyExchangeInfo(kex_type, size, curve))


def by_subject(report):
    return {f.subject: f for f in report.findings}


# --- security strength ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("bits", "strength"), [(1024, 80), (2048, 112), (3072, 128), (4096, 128), (7680, 192)]
)
def test_rsa_strength_table(bits, strength):
    assert ifc_ffc_strength(bits) == strength


# --- scenarios --------------------------------------------------------------------------


def test_legacy_server_is_broken():
    s = scan(
        {
            "TLS 1.0": ProtocolInfo(True, [CipherSuiteInfo("TLS_RSA_WITH_RC4_128_SHA", 128)]),
            "TLS 1.2": ProtocolInfo(
                True,
                [
                    CipherSuiteInfo("TLS_RSA_WITH_AES_128_GCM_SHA256", 128),
                    suite("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "DH", None, 1024),
                ],
            ),
        },
        chain=[cert("RSA", 1024, hash_="sha1")],
    )
    report = grade(s)
    f = by_subject(report)
    assert report.verdict == "broken"
    assert f["TLS 1.0"].status == "broken"
    assert f["TLS_RSA_WITH_RC4_128_SHA"].status == "broken"
    assert "forward secrecy" in f["TLS_RSA_WITH_AES_128_GCM_SHA256"].detail
    assert f["dh-1024"].status == "broken"
    assert f["leaf: RSA-1024"].status == "broken"
    assert f["leaf: sha1"].status == "broken"
    assert all(x.priority == 1 for x in report.findings if x.status == "broken")


def test_modern_classical_server_is_quantum_vulnerable():
    s = scan(
        {"TLS 1.3": ProtocolInfo(True, [suite("TLS_AES_128_GCM_SHA256", "X25519", None, 253)])},
        groups=["X25519", "secp256r1"],
        chain=[cert("EC", 256, "secp256r1")],
    )
    report = grade(s)
    f = by_subject(report)
    assert report.verdict == "quantum_vulnerable"
    assert report.hndl_exposed is True
    # 128-bit strength: no 2030 deprecation, disallowed after 2035
    assert f["x25519"].nist.deprecated_after is None
    assert f["x25519"].nist.disallowed_after == 2035
    assert f["leaf: EC-256 (secp256r1)"].nist.security_strength_bits == 128
    # key exchange outranks certificates (harvest now, decrypt later)
    assert f["x25519"].priority < f["leaf: EC-256 (secp256r1)"].priority


def test_rsa_2048_hits_2030_deprecation():
    s = scan({"TLS 1.3": ProtocolInfo(True, [])}, chain=[cert("RSA", 2048)])
    report = grade(s)
    finding = by_subject(report)["leaf: RSA-2048"]
    assert finding.nist.security_strength_bits == 112
    assert finding.nist.deprecated_after == 2030
    assert report.earliest_deadline == 2030


def test_prime256v1_alias_is_normalized():
    s = scan({"TLS 1.2": ProtocolInfo(True, [suite("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")])})
    assert "secp256r1" in by_subject(grade(s))


def test_cbc_suite_is_weak():
    s = scan({"TLS 1.2": ProtocolInfo(True, [suite("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA")])})
    f = by_subject(grade(s))["TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"]
    assert (f.status, f.priority) == ("weak", 2)


def test_hybrid_pq_group_is_quantum_ready_but_cert_still_vulnerable():
    s = scan(
        {"TLS 1.3": ProtocolInfo(True, [])},
        groups=["X25519MLKEM768"],
        chain=[cert("EC", 256, "secp256r1")],
    )
    report = grade(s)
    f = by_subject(report)
    assert f["x25519mlkem768"].status == "quantum_ready"
    assert report.hndl_exposed is False
    assert report.verdict == "quantum_vulnerable"  # certificate still classical


def test_root_sha1_self_signature_is_ignored():
    chain = [cert("RSA", 2048), cert("RSA", 4096, hash_="sha1", subject="CN=r", issuer="CN=r")]
    report = grade(scan({"TLS 1.3": ProtocolInfo(True, [])}, chain=chain))
    assert not any(f.category == "signature_hash" for f in report.findings)


def test_fail_on_exit_code(monkeypatch):
    s = scan({"TLS 1.0": ProtocolInfo(True, [])})
    monkeypatch.setattr("pqc_inventory.cli.scan_tls", lambda host, port: s)
    assert main(["test", "-f", "text", "--fail-on", "broken"]) == 2
    assert main(["test", "-f", "text"]) == 0
