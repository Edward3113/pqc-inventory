"""Find open ports and tell SSH from TLS before running full scans.

SSH servers send their identification banner as soon as the TCP connection opens; TLS
servers stay silent until the client sends a ClientHello. One short read is enough to
classify an open port.
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor

from pqc_inventory.targets import Endpoint


def detect(
    host: str, port: int, connect_timeout: float = 1.0, banner_wait: float = 1.5
) -> str | None:
    """Return 'ssh', 'tls', or None if the port is closed or unreachable."""
    try:
        with socket.create_connection((host, port), timeout=connect_timeout) as sock:
            sock.settimeout(banner_wait)
            try:
                first = sock.recv(8)
            except TimeoutError:
                return "tls"  # silent server: assume TLS; the TLS scan will confirm
            if first.startswith(b"SSH-"):
                return "ssh"
            return "tls" if first else None  # connection closed immediately
    except OSError:
        return None


def discover(
    endpoints: list[Endpoint], workers: int = 64, connect_timeout: float = 1.0
) -> list[tuple[Endpoint, str]]:
    """Probe endpoints concurrently; return (endpoint, protocol) for the open ones."""

    def check(ep: Endpoint) -> tuple[Endpoint, str | None]:
        return ep, detect(ep.host, ep.port, connect_timeout)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(check, endpoints))
    return [(ep, proto) for ep, proto in results if proto]
