"""Expand user input (hosts, host:port, CIDR ranges, target files) into endpoints.

Ranges outside private address space are refused unless explicitly allowed: sweeping a
network you don't administer should never happen by accident.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path

DEFAULT_PORTS = (22, 443)
DEFAULT_MAX_HOSTS = 1024


class TargetError(ValueError):
    """Invalid or disallowed target specification."""


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int
    explicit_port: bool  # user typed host:port, so skip discovery for it


def split_host_port(spec: str) -> tuple[str, int | None]:
    """'host', 'host:port', '[v6]:port'. Port is None if omitted."""
    if spec.startswith("["):
        host, _, rest = spec[1:].partition("]")
        port = rest.lstrip(":")
        return host, int(port) if port else None
    if spec.count(":") == 1:
        host, port = spec.split(":")
        return host, int(port)
    return spec, None


def parse_ports(text: str) -> list[int]:
    """'22,443,8000-8002' -> [22, 443, 8000, 8001, 8002]."""
    ports: list[int] = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = (int(x) for x in part.split("-", 1))
            if lo > hi:
                raise TargetError(f"bad port range {part!r}")
            ports.extend(range(lo, hi + 1))
        else:
            ports.append(int(part))
    for port in ports:
        if not 1 <= port <= 65535:
            raise TargetError(f"port out of range: {port}")
    return list(dict.fromkeys(ports))


def read_target_file(path: str) -> list[str]:
    """One target per line; blank lines and # comments ignored."""
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return [ln.split("#", 1)[0].strip() for ln in lines if ln.split("#", 1)[0].strip()]


def _is_network(spec: str) -> bool:
    return "/" in spec


def expand_network(spec: str, allow_public: bool, max_hosts: int) -> list[str]:
    try:
        net = ipaddress.ip_network(spec, strict=False)
    except ValueError as exc:
        raise TargetError(f"invalid network {spec!r}: {exc}") from exc
    if not net.is_private and not allow_public:
        raise TargetError(
            f"{net} is not private address space; pass --allow-public only if you are "
            "authorized to scan it"
        )
    count = net.num_addresses - (2 if net.version == 4 and net.prefixlen < 31 else 0)
    if count > max_hosts:
        raise TargetError(f"{net} has {count} hosts; limit is {max_hosts} (see --max-hosts)")
    return [str(ip) for ip in net.hosts()]


def expand_targets(
    specs: list[str],
    ports: list[int] | None = None,
    allow_public: bool = False,
    max_hosts: int = DEFAULT_MAX_HOSTS,
) -> list[Endpoint]:
    """Turn target specs into a de-duplicated, ordered list of endpoints."""
    ports = ports or list(DEFAULT_PORTS)
    endpoints: dict[tuple[str, int], Endpoint] = {}
    total_hosts = 0

    for spec in specs:
        if _is_network(spec):
            hosts = expand_network(spec, allow_public, max_hosts)
            total_hosts += len(hosts)
            for host in hosts:
                for port in ports:
                    endpoints.setdefault((host, port), Endpoint(host, port, False))
        else:
            host, port = split_host_port(spec)
            total_hosts += 1
            if port:
                endpoints[(host, port)] = Endpoint(host, port, True)
            else:
                for p in ports:
                    endpoints.setdefault((host, p), Endpoint(host, p, False))
        if total_hosts > max_hosts:
            raise TargetError(f"more than {max_hosts} hosts requested (see --max-hosts)")

    return list(endpoints.values())
