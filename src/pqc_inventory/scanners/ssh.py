"""SSH scanner: records the algorithms an SSH server offers, without authenticating.

An SSH server announces every algorithm it supports in its SSH_MSG_KEXINIT packet, sent
right after the version banners are exchanged (RFC 4253 section 7.1). This module reads
that packet and disconnects, so no credentials are ever sent.

Host key sizes aren't in KEXINIT, so they're collected separately with ssh-keyscan.

Hostile-server hardening (see SECURITY.md scope): every read has a timeout and a byte
limit, packet lengths are bounds-checked before allocation, and name-list parsing never
reads past the end of the payload.
"""

from __future__ import annotations

import shutil
import socket
import struct
import subprocess  # noqa: S404 -- used with fixed argv lists only
from datetime import UTC, datetime

from cryptography.hazmat.primitives.serialization import load_ssh_public_key

from pqc_inventory import __version__
from pqc_inventory.models import SshHostKey, SshScanResult
from pqc_inventory.scanners.pq_probe import is_safe_host
from pqc_inventory.scanners.tls import describe_public_key

CLIENT_BANNER = f"SSH-2.0-pqc_inventory_{__version__}\r\n".encode()
MSG_KEXINIT = 20
MAX_BANNER_LINE = 255  # RFC 4253 4.2
MAX_PRE_BANNER_LINES = 32
MAX_PACKET = 35000  # RFC 4253 6.1
NAME_LIST_FIELDS = (
    "kex",
    "host_key_algorithms",
    "ciphers_c2s",
    "ciphers_s2c",
    "macs_c2s",
    "macs_s2c",
    "compression_c2s",
    "compression_s2c",
)


class SshProtocolError(Exception):
    """The server sent something that isn't a well-formed SSH handshake."""


# --- wire parsing (pure functions, unit-testable without a network) ----------------------


def parse_name_lists(payload: bytes) -> dict[str, list[str]]:
    """Parse the name-lists from a KEXINIT payload (message byte included)."""
    if len(payload) < 17 or payload[0] != MSG_KEXINIT:
        raise SshProtocolError("not a KEXINIT message")
    offset = 17  # 1 message byte + 16-byte cookie
    lists: dict[str, list[str]] = {}
    for name in (*NAME_LIST_FIELDS, "languages_c2s", "languages_s2c"):
        if offset + 4 > len(payload):
            raise SshProtocolError(f"KEXINIT truncated before {name}")
        (length,) = struct.unpack(">I", payload[offset : offset + 4])
        offset += 4
        if offset + length > len(payload):
            raise SshProtocolError(f"KEXINIT {name} length {length} exceeds payload")
        raw = payload[offset : offset + length]
        offset += length
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise SshProtocolError(f"non-ASCII algorithm name in {name}") from exc
        lists[name] = [item for item in text.split(",") if item]
    return lists


def extract_payload(packet: bytes) -> bytes:
    """Strip padding from a decoded binary packet body (padding_length byte first)."""
    if not packet:
        raise SshProtocolError("empty packet")
    padding = packet[0]
    if padding + 1 > len(packet):
        raise SshProtocolError("padding length exceeds packet")
    return packet[1 : len(packet) - padding]


# --- network I/O ------------------------------------------------------------------------


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise SshProtocolError("connection closed mid-handshake")
        data += chunk
    return bytes(data)


def _read_line(sock: socket.socket) -> bytes:
    line = bytearray()
    while len(line) <= MAX_BANNER_LINE:
        byte = sock.recv(1)
        if not byte:
            raise SshProtocolError("connection closed before banner")
        line += byte
        if byte == b"\n":
            return bytes(line).rstrip(b"\r\n")
    raise SshProtocolError("banner line exceeds 255 bytes")


def read_banner(sock: socket.socket) -> str:
    """Read the server identification string, skipping allowed pre-banner lines."""
    for _ in range(MAX_PRE_BANNER_LINES):
        line = _read_line(sock)
        if line.startswith(b"SSH-"):
            if not (line.startswith(b"SSH-2.0-") or line.startswith(b"SSH-1.99-")):
                raise SshProtocolError(f"unsupported protocol version: {line[:40]!r}")
            return line.decode("ascii", errors="replace")
    raise SshProtocolError("no SSH banner within the first 32 lines")


def read_kexinit(sock: socket.socket) -> dict[str, list[str]]:
    (length,) = struct.unpack(">I", _recv_exact(sock, 4))
    if not 5 <= length <= MAX_PACKET:
        raise SshProtocolError(f"implausible packet length {length}")
    return parse_name_lists(extract_payload(_recv_exact(sock, length)))


def keyscan(host: str, port: int, timeout: int = 5) -> list:
    """Return PublicKeyInfo for each host key, via ssh-keyscan. Empty list if unavailable."""
    binary = shutil.which("ssh-keyscan")
    if not binary:
        return []
    argv = [binary, "-T", str(timeout), "-p", str(port), "-t", "rsa,ecdsa,ed25519", host]
    try:
        proc = subprocess.run(  # noqa: S603
            argv, capture_output=True, text=True, timeout=timeout * 4, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return []

    keys = []
    for line in proc.stdout.splitlines():
        if line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            key = load_ssh_public_key(f"{parts[1]} {parts[2]}".encode())
        except (ValueError, TypeError):  # unsupported or malformed key: skip, don't crash
            continue
        info = describe_public_key(key)
        keys.append({"type": parts[1], "key": info})
    return keys


def scan_ssh(host: str, port: int = 22, timeout: float = 10.0) -> SshScanResult:
    """Scan one SSH endpoint. Never authenticates."""
    scanned_at = datetime.now(UTC).isoformat()
    result = SshScanResult(host, port, scanned_at, "error")

    if not is_safe_host(host):
        result.error = f"refusing to scan unsafe host value {host!r}"
        return result

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            result.banner = read_banner(sock)
            sock.sendall(CLIENT_BANNER)
            lists = read_kexinit(sock)
    except (OSError, SshProtocolError, struct.error) as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        return result

    result.status = "completed"
    result.kex = lists["kex"]
    result.host_key_algorithms = lists["host_key_algorithms"]
    # Servers use the same list in both directions in practice; keep the union, ordered.
    result.ciphers = list(dict.fromkeys(lists["ciphers_s2c"] + lists["ciphers_c2s"]))
    result.macs = list(dict.fromkeys(lists["macs_s2c"] + lists["macs_c2s"]))
    result.compression = list(dict.fromkeys(lists["compression_s2c"] + lists["compression_c2s"]))
    for entry in keyscan(host, port):
        result.host_keys.append(SshHostKey(entry["type"], entry["key"]))
    return result
