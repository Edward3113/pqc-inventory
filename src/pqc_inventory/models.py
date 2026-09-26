"""Plain data models for scan results. Kept free of sslyze types so output stays stable."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class PublicKeyInfo:
    algorithm: str  # "RSA", "EC", "Ed25519", "Ed448", "DSA", or "unknown"
    size_bits: int | None = None
    curve: str | None = None


@dataclass
class CertificateInfo:
    subject: str
    issuer: str
    not_before: str
    not_after: str
    public_key: PublicKeyInfo
    signature_algorithm: str
    signature_hash: str | None = None


@dataclass
class KeyExchangeInfo:
    type: str  # e.g. "ECDH", "DH", "X25519"
    size_bits: int | None = None
    curve: str | None = None


@dataclass
class CipherSuiteInfo:
    name: str
    key_size_bits: int
    key_exchange: KeyExchangeInfo | None = None


@dataclass
class ProtocolInfo:
    supported: bool
    cipher_suites: list[CipherSuiteInfo] = field(default_factory=list)


@dataclass
class PqProbeResult:
    status: str  # "completed" | "skipped" | "error"
    openssl: str | None = None  # version string of the OpenSSL binary used
    reason: str | None = None
    accepted: list[str] = field(default_factory=list)
    rejected: list[str] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)


@dataclass
class TlsScanResult:
    host: str
    port: int
    scanned_at: str
    status: str  # "completed" | "error"
    error: str | None = None
    protocols: dict[str, ProtocolInfo] = field(default_factory=dict)
    supported_groups: list[str] = field(default_factory=list)
    certificate_chain: list[CertificateInfo] = field(default_factory=list)
    pq_probe: PqProbeResult | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
