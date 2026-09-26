"""TLS scanner: records the protocols, cipher suites, groups, and certificates an endpoint offers.

Milestone 1 collects facts only. Grading against rules.yaml happens in the policy engine
(milestone 2), so the raw inventory stays reusable for CBOM output later.
"""

from __future__ import annotations

from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from nassl.ephemeral_key_info import OpenSslEcNidEnum, OpenSslEvpPkeyEnum
from sslyze import (
    ScanCommand,
    ScanCommandAttemptStatusEnum,
    Scanner,
    ServerNetworkLocation,
    ServerScanRequest,
    ServerScanStatusEnum,
)

from pqc_inventory.models import (
    CertificateInfo,
    CipherSuiteInfo,
    KeyExchangeInfo,
    ProtocolInfo,
    PublicKeyInfo,
    TlsScanResult,
)

# ScanCommand -> (display name, attribute on sslyze's scan result)
PROTOCOL_COMMANDS: dict[ScanCommand, tuple[str, str]] = {
    ScanCommand.SSL_2_0_CIPHER_SUITES: ("SSL 2.0", "ssl_2_0_cipher_suites"),
    ScanCommand.SSL_3_0_CIPHER_SUITES: ("SSL 3.0", "ssl_3_0_cipher_suites"),
    ScanCommand.TLS_1_0_CIPHER_SUITES: ("TLS 1.0", "tls_1_0_cipher_suites"),
    ScanCommand.TLS_1_1_CIPHER_SUITES: ("TLS 1.1", "tls_1_1_cipher_suites"),
    ScanCommand.TLS_1_2_CIPHER_SUITES: ("TLS 1.2", "tls_1_2_cipher_suites"),
    ScanCommand.TLS_1_3_CIPHER_SUITES: ("TLS 1.3", "tls_1_3_cipher_suites"),
}


def describe_public_key(key: object) -> PublicKeyInfo:
    """Normalize a cryptography public key into algorithm / size / curve."""
    if isinstance(key, rsa.RSAPublicKey):
        return PublicKeyInfo("RSA", key.key_size)
    if isinstance(key, ec.EllipticCurvePublicKey):
        return PublicKeyInfo("EC", key.key_size, key.curve.name)
    if isinstance(key, ed25519.Ed25519PublicKey):
        return PublicKeyInfo("Ed25519", 256)
    if isinstance(key, ed448.Ed448PublicKey):
        return PublicKeyInfo("Ed448", 456)
    if isinstance(key, dsa.DSAPublicKey):
        return PublicKeyInfo("DSA", key.key_size)
    return PublicKeyInfo("unknown")


def describe_certificate(cert: x509.Certificate) -> CertificateInfo:
    oid = cert.signature_algorithm_oid
    sig_hash = cert.signature_hash_algorithm
    return CertificateInfo(
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        not_before=cert.not_valid_before_utc.isoformat(),
        not_after=cert.not_valid_after_utc.isoformat(),
        public_key=describe_public_key(cert.public_key()),
        signature_algorithm=getattr(oid, "_name", None) or oid.dotted_string,
        signature_hash=sig_hash.name if sig_hash else None,
    )


def _enum_name(value: object, enum_cls: type) -> str | None:
    """nassl sometimes hands back raw ints instead of enum members; normalize both."""
    if value is None:
        return None
    if hasattr(value, "name"):
        return value.name
    try:
        return enum_cls(value).name
    except ValueError:
        return str(value)


def describe_key_exchange(ephemeral_key: object | None) -> KeyExchangeInfo | None:
    """Normalize sslyze/nassl ephemeral key info (ECDH, DH, X25519...)."""
    if ephemeral_key is None:
        return None
    return KeyExchangeInfo(
        type=_enum_name(getattr(ephemeral_key, "type", None), OpenSslEvpPkeyEnum) or "unknown",
        size_bits=getattr(ephemeral_key, "size", None),
        curve=_enum_name(getattr(ephemeral_key, "curve", None), OpenSslEcNidEnum),
    )


def scan_tls(host: str, port: int = 443) -> TlsScanResult:
    """Scan a single TLS endpoint and return a normalized inventory."""
    scanned_at = datetime.now(UTC).isoformat()
    commands = set(PROTOCOL_COMMANDS) | {ScanCommand.CERTIFICATE_INFO, ScanCommand.ELLIPTIC_CURVES}

    try:
        request = ServerScanRequest(
            server_location=ServerNetworkLocation(hostname=host, port=port),
            scan_commands=commands,
        )
    except Exception as exc:  # e.g. DNS resolution failure
        return TlsScanResult(host, port, scanned_at, "error", error=str(exc))

    scanner = Scanner()
    scanner.queue_scans([request])
    server_result = next(iter(scanner.get_results()))

    if server_result.scan_status != ServerScanStatusEnum.COMPLETED:
        trace = server_result.connectivity_error_trace
        error = str(trace.exc_value) if trace else server_result.scan_status.name
        return TlsScanResult(host, port, scanned_at, "error", error=error)

    attempts = server_result.scan_result
    result = TlsScanResult(host, port, scanned_at, "completed")

    for display_name, attr in PROTOCOL_COMMANDS.values():
        attempt = getattr(attempts, attr)
        if attempt.status != ScanCommandAttemptStatusEnum.COMPLETED:
            continue
        accepted = attempt.result.accepted_cipher_suites
        result.protocols[display_name] = ProtocolInfo(
            supported=bool(accepted),
            cipher_suites=[
                CipherSuiteInfo(
                    name=s.cipher_suite.name,
                    key_size_bits=s.cipher_suite.key_size,
                    key_exchange=describe_key_exchange(s.ephemeral_key),
                )
                for s in accepted
            ],
        )

    curves = attempts.elliptic_curves
    if curves.status == ScanCommandAttemptStatusEnum.COMPLETED and curves.result.supported_curves:
        result.supported_groups = [c.name for c in curves.result.supported_curves]

    cert_info = attempts.certificate_info
    if cert_info.status == ScanCommandAttemptStatusEnum.COMPLETED:
        deployments = cert_info.result.certificate_deployments
        if deployments:
            result.certificate_chain = [
                describe_certificate(c) for c in deployments[0].received_certificate_chain
            ]

    return result
