"""Offline tests: no network needed, so they run in CI on every push."""

from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

from pqc_inventory.cli import parse_target
from pqc_inventory.policy import load_rules
from pqc_inventory.scanners.tls import describe_certificate, describe_public_key


def _self_signed(key, hash_alg):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.local")])
    now = datetime.now(UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hash_alg)
    )


def test_rsa_key():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    info = describe_public_key(key.public_key())
    assert (info.algorithm, info.size_bits) == ("RSA", 2048)


def test_ec_key():
    key = ec.generate_private_key(ec.SECP256R1())
    info = describe_public_key(key.public_key())
    assert (info.algorithm, info.size_bits, info.curve) == ("EC", 256, "secp256r1")


def test_certificate_rsa_sha256():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    info = describe_certificate(_self_signed(key, hashes.SHA256()))
    assert info.subject == "CN=test.local"
    assert info.public_key.algorithm == "RSA"
    assert info.signature_hash == "sha256"


def test_certificate_ed25519_has_no_hash():
    key = ed25519.Ed25519PrivateKey.generate()
    info = describe_certificate(_self_signed(key, None))
    assert info.public_key.algorithm == "Ed25519"
    assert info.signature_hash is None


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("example.com", ("example.com", 443)),
        ("example.com:8443", ("example.com", 8443)),
        ("[::1]:443", ("::1", 443)),
    ],
)
def test_parse_target(target, expected):
    assert parse_target(target) == expected


def test_rules_load():
    rules = load_rules()
    assert rules["nist_ir_8547"]["timeline"][0]["deprecated_after"] == 2030
    assert "x25519mlkem768" in rules["key_exchange"]["quantum_ready"]
    assert None not in rules["cipher_suites"]["broken_if_name_contains"]


def test_key_exchange_accepts_raw_ints():
    """Regression: nassl can return plain ints instead of enum members."""
    from types import SimpleNamespace

    from nassl.ephemeral_key_info import OpenSslEvpPkeyEnum

    from pqc_inventory.scanners.tls import describe_key_exchange

    fake = SimpleNamespace(type=int(OpenSslEvpPkeyEnum.X25519), size=253, curve=None)
    info = describe_key_exchange(fake)
    assert info.type == "X25519"
    assert info.size_bits == 253


def test_unreachable_host_reports_error_instead_of_crashing():
    """Regression: the connectivity-error path used a nonexistent traceback attribute."""
    import socket

    from pqc_inventory.scanners.tls import scan_tls

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]  # closed once the with-block exits
    result = scan_tls("127.0.0.1", port, pq_probe=False)
    assert result.status == "error"
    assert result.error
