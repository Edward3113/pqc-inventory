"""Tests for the OpenSSL post-quantum probe.

Unit tests always run. The live handshake tests start real OpenSSL 3.5+ servers on
localhost and are skipped when no capable binary is available (e.g. stock CI runners).
"""

import socket
import stat
import subprocess
import time
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from pqc_inventory.scanners.pq_probe import (
    find_openssl,
    is_safe_host,
    parse_version,
    probe_pq_groups,
)

# --- unit tests -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        ("OpenSSL 3.5.4 30 Sep 2025 (Library: OpenSSL 3.5.4 30 Sep 2025)", (3, 5, 4)),
        ("OpenSSL 3.0.13 30 Jan 2024", (3, 0, 13)),
        ("LibreSSL 3.3.6", None),
        ("", None),
    ],
)
def test_parse_version(output, expected):
    assert parse_version(output) == expected


@pytest.mark.parametrize(
    ("host", "ok"),
    [
        ("example.com", True),
        ("sub.example.co.uk", True),
        ("192.168.1.10", True),
        ("::1", True),
        ("-proxy", False),
        ("evil.com -proxy x:80", False),
        ("a;rm -rf /", False),
        ("", False),
    ],
)
def test_is_safe_host(host, ok):
    assert is_safe_host(host) is ok


def test_unsafe_host_is_refused_before_running_anything():
    result = probe_pq_groups("-proxy", 443, ["X25519MLKEM768"])
    assert result.status == "error"
    assert "unsafe" in result.reason


def _fake_binary(tmp_path, name, version_output):
    path = tmp_path / name
    path.write_text(f"#!/bin/sh\necho '{version_output}'\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return str(path)


def test_find_openssl_rejects_libressl(tmp_path):
    fake = _fake_binary(tmp_path, "libressl", "LibreSSL 3.3.6")
    path, _, reason = find_openssl(fake)
    assert path is None
    assert "3.5+" in reason and "LibreSSL" in reason


def test_find_openssl_rejects_openssl_3_0(tmp_path):
    fake = _fake_binary(tmp_path, "old", "OpenSSL 3.0.13 30 Jan 2024")
    assert find_openssl(fake)[0] is None


def test_find_openssl_accepts_3_5(tmp_path):
    fake = _fake_binary(tmp_path, "new", "OpenSSL 3.5.4 30 Sep 2025")
    path, version, _ = find_openssl(fake)
    assert path == fake
    assert version.startswith("OpenSSL 3.5")


def test_missing_openssl_means_skipped(tmp_path):
    fake = _fake_binary(tmp_path, "libressl", "LibreSSL 3.3.6")
    result = probe_pq_groups("localhost", 443, ["X25519MLKEM768"], openssl=fake)
    assert result.status == "skipped"


# --- live handshake tests against local OpenSSL servers ------------------------------------

OPENSSL, _, _ = find_openssl()
live = pytest.mark.skipif(OPENSSL is None, reason="OpenSSL 3.5+ not available")


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def cert_files(tmp_path_factory):
    d = tmp_path_factory.mktemp("certs")
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    (d / "key.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (d / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return str(d / "cert.pem"), str(d / "key.pem")


def _server(cert_files, groups):
    cert, key = cert_files
    port = _free_port()
    proc = subprocess.Popen(  # noqa: S603
        [
            OPENSSL,
            "s_server",
            "-accept",
            str(port),
            "-cert",
            cert,
            "-key",
            key,
            "-groups",
            groups,
            "-www",
            "-quiet",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(50):
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                break
        time.sleep(0.1)
    return proc, port


@live
def test_live_pq_server_is_detected(cert_files):
    proc, port = _server(cert_files, "X25519MLKEM768:X25519")
    try:
        result = probe_pq_groups("127.0.0.1", port, ["X25519MLKEM768", "SecP384r1MLKEM1024"])
    finally:
        proc.terminate()
    assert result.status == "completed"
    assert result.accepted == ["X25519MLKEM768"]
    assert result.rejected == ["SecP384r1MLKEM1024"]


@live
def test_live_classical_server_rejects_pq(cert_files):
    proc, port = _server(cert_files, "X25519:P-256")
    try:
        result = probe_pq_groups("127.0.0.1", port, ["X25519MLKEM768"])
    finally:
        proc.terminate()
    assert result.accepted == []
    assert result.rejected == ["X25519MLKEM768"]


def test_closed_port_is_an_error_not_a_rejection():
    if OPENSSL is None:
        pytest.skip("OpenSSL 3.5+ not available")
    result = probe_pq_groups("127.0.0.1", _free_port(), ["X25519MLKEM768"], timeout=5)
    assert result.status == "error"
    assert "X25519MLKEM768" in result.errors
