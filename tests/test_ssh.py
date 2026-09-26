"""SSH scanner and grader tests.

Fake servers speak just enough SSH to exercise the parser, including hostile servers that
send oversized, truncated, or malformed data. A live test against a real sshd runs only if
one is listening on 127.0.0.1:2222 (see CONTRIBUTING notes); CI skips it.
"""

import os
import socket
import struct
import threading

import pytest

from pqc_inventory.models import PublicKeyInfo, SshHostKey, SshScanResult
from pqc_inventory.policy.ssh import grade_ssh
from pqc_inventory.scanners.ssh import (
    SshProtocolError,
    extract_payload,
    parse_name_lists,
    scan_ssh,
)

# --- helpers ----------------------------------------------------------------------------


def name_list(items):
    raw = ",".join(items).encode()
    return struct.pack(">I", len(raw)) + raw


def kexinit_payload(
    kex, hostkeys=("ssh-ed25519",), ciphers=("aes128-ctr",), macs=("hmac-sha2-256",)
):
    lists = [kex, hostkeys, ciphers, ciphers, macs, macs, ["none"], ["none"], [], []]
    return (
        bytes([20]) + b"\x00" * 16 + b"".join(name_list(x) for x in lists) + b"\x00" + b"\x00" * 4
    )


def packet(payload, padding=4):
    body = bytes([padding]) + payload + b"\x00" * padding
    return struct.pack(">I", len(body)) + body


def fake_server(response: bytes, hang: bool = False):
    """Serve `response` to the first client, then close. Returns the port."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def run():
        conn, _ = srv.accept()
        with conn:
            conn.sendall(response)
            if hang:
                threading.Event().wait(5)
            elif response:  # an empty response means "accept, then hang up immediately"
                try:
                    conn.recv(1024)
                except OSError:
                    pass
        srv.close()

    threading.Thread(target=run, daemon=True).start()
    return port


BANNER = b"SSH-2.0-FakeSSH_1.0\r\n"
MODERN_KEX = [
    "sntrup761x25519-sha512@openssh.com",
    "curve25519-sha256",
    "kex-strict-s-v00@openssh.com",
]

# --- parser -----------------------------------------------------------------------------


def test_parse_name_lists_roundtrip():
    lists = parse_name_lists(
        kexinit_payload(["curve25519-sha256"], ["ssh-ed25519", "rsa-sha2-512"])
    )
    assert lists["kex"] == ["curve25519-sha256"]
    assert lists["host_key_algorithms"] == ["ssh-ed25519", "rsa-sha2-512"]


def test_parse_rejects_non_kexinit():
    with pytest.raises(SshProtocolError, match="not a KEXINIT"):
        parse_name_lists(bytes([21]) + b"\x00" * 40)


def test_parse_rejects_name_list_longer_than_payload():
    payload = bytes([20]) + b"\x00" * 16 + struct.pack(">I", 10_000) + b"abc"
    with pytest.raises(SshProtocolError, match="exceeds payload"):
        parse_name_lists(payload)


def test_parse_rejects_truncated_kexinit():
    with pytest.raises(SshProtocolError, match="truncated"):
        parse_name_lists(bytes([20]) + b"\x00" * 16 + name_list(["curve25519-sha256"]))


def test_extract_payload_rejects_bad_padding():
    with pytest.raises(SshProtocolError, match="padding"):
        extract_payload(bytes([200]) + b"abc")


# --- scanner against fake servers --------------------------------------------------------


def test_scan_fake_server_with_pre_banner_lines():
    port = fake_server(b"Welcome!\r\n" + BANNER + packet(kexinit_payload(MODERN_KEX)))
    result = scan_ssh("127.0.0.1", port, timeout=3)
    assert result.status == "completed", result.error
    assert result.banner == "SSH-2.0-FakeSSH_1.0"
    assert "curve25519-sha256" in result.kex


@pytest.mark.parametrize(
    ("response", "error_fragment"),
    [
        (b"SSH-1.5-Ancient\r\n", "unsupported protocol"),
        (b"A" * 400 + b"\r\n", "exceeds 255"),
        (BANNER + struct.pack(">I", 10_000_000), "implausible packet length"),
        (BANNER + struct.pack(">I", 100) + b"\x04short", "closed mid-handshake"),
        (b"", "closed before banner"),
    ],
    ids=["ssh1", "long-banner", "huge-length", "truncated-packet", "empty"],
)
def test_hostile_servers_produce_errors_not_crashes(response, error_fragment):
    port = fake_server(response)
    result = scan_ssh("127.0.0.1", port, timeout=3)
    assert result.status == "error"
    assert error_fragment in result.error


def test_silent_server_times_out():
    port = fake_server(b"", hang=True)
    result = scan_ssh("127.0.0.1", port, timeout=1)
    assert result.status == "error"
    assert "timed out" in result.error.lower()


def test_unsafe_host_refused():
    assert scan_ssh("-oProxyCommand=evil", 22).status == "error"


# --- grading ----------------------------------------------------------------------------


def ssh_scan(
    kex, hostkeys=("ssh-ed25519",), ciphers=("aes128-ctr",), macs=("hmac-sha2-256",), keys=()
):
    return SshScanResult(
        "test",
        22,
        "now",
        "completed",
        banner="SSH-2.0-Test",
        kex=list(kex),
        host_key_algorithms=list(hostkeys),
        ciphers=list(ciphers),
        macs=list(macs),
        host_keys=list(keys),
    )


def by_subject(report):
    return {f.subject: f for f in report.findings}


def test_modern_openssh_is_pq_ready_with_low_severity_fallback():
    report = grade_ssh(ssh_scan(MODERN_KEX))
    f = by_subject(report)
    assert report.pq_key_exchange is True
    assert report.hndl_exposed is False
    assert f["sntrup761x25519-sha512@openssh.com"].status == "quantum_ready"
    assert f["curve25519-sha256"].severity == "low"
    assert "kex-strict-s-v00@openssh.com" not in f  # pseudo-algorithm ignored


def test_classical_only_server_is_hndl_exposed():
    report = grade_ssh(ssh_scan(["curve25519-sha256", "ecdh-sha2-nistp256"]))
    assert report.hndl_exposed is True
    assert by_subject(report)["curve25519-sha256"].severity == "medium"


def test_legacy_algorithms_are_broken():
    report = grade_ssh(
        ssh_scan(
            ["diffie-hellman-group1-sha1"],
            hostkeys=["ssh-rsa", "ssh-dss"],
            ciphers=["3des-cbc", "aes128-cbc"],
            macs=["hmac-md5", "hmac-sha1-96"],
            keys=[SshHostKey("ssh-rsa", PublicKeyInfo("RSA", 1024))],
        )
    )
    f = by_subject(report)
    assert report.verdict == "broken"
    for subject in (
        "diffie-hellman-group1-sha1",
        "ssh-rsa",
        "ssh-dss",
        "3des-cbc",
        "hmac-md5",
        "hmac-sha1-96",
        "RSA-1024 host key",
    ):
        assert f[subject].status == "broken", subject
    assert f["aes128-cbc"].status == "weak"


def test_rsa_host_key_strength_comes_from_keyscan():
    keys = [SshHostKey("ssh-rsa", PublicKeyInfo("RSA", 3072))]
    report = grade_ssh(ssh_scan(["curve25519-sha256"], hostkeys=["rsa-sha2-512"], keys=keys))
    timeline = by_subject(report)["rsa-sha2-512"].nist
    assert timeline.security_strength_bits == 128
    assert timeline.deprecated_after is None


@pytest.mark.parametrize(
    ("kex", "ciphers", "macs", "vulnerable"),
    [
        (["curve25519-sha256"], ["chacha20-poly1305@openssh.com"], ["hmac-sha2-256"], True),
        (["curve25519-sha256"], ["aes128-cbc"], ["hmac-sha2-256-etm@openssh.com"], True),
        (MODERN_KEX, ["chacha20-poly1305@openssh.com"], ["hmac-sha2-256"], False),
        (["curve25519-sha256"], ["aes128-gcm@openssh.com"], ["hmac-sha2-256"], False),
    ],
    ids=["chacha-no-strict", "cbc-etm-no-strict", "strict-kex", "gcm-only"],
)
def test_terrapin_detection(kex, ciphers, macs, vulnerable):
    report = grade_ssh(ssh_scan(kex, ciphers=ciphers, macs=macs))
    found = "Terrapin (CVE-2023-48795)" in by_subject(report)
    assert found is vulnerable


# --- optional live test -----------------------------------------------------------------

LIVE_PORT = int(os.environ.get("PQC_SSH_TEST_PORT", "2222"))


def _sshd_listening():
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", LIVE_PORT)) == 0


@pytest.mark.skipif(not _sshd_listening(), reason=f"no sshd on 127.0.0.1:{LIVE_PORT}")
def test_live_openssh():
    result = scan_ssh("127.0.0.1", LIVE_PORT)
    assert result.status == "completed"
    assert result.banner.startswith("SSH-2.0-")
    assert grade_ssh(result).verdict != "unknown"
