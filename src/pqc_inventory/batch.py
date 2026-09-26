"""Scan many endpoints: discover, scan each open port, grade, and summarize."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from pqc_inventory.discovery import discover
from pqc_inventory.models import SshScanResult, TlsScanResult
from pqc_inventory.policy import load_rules
from pqc_inventory.policy.engine import STATUS_ORDER, GradeReport, grade
from pqc_inventory.policy.ssh import grade_ssh
from pqc_inventory.scanners import scan_ssh, scan_tls
from pqc_inventory.targets import Endpoint


@dataclass
class EndpointResult:
    host: str
    port: int
    protocol: str
    scan: TlsScanResult | SshScanResult
    grade: GradeReport | None


@dataclass
class BatchSummary:
    endpoints_requested: int
    endpoints_open: int
    scanned: int
    errors: int
    verdicts: dict[str, int]
    pq_key_exchange: int
    hndl_exposed: int
    earliest_deadline: int | None
    worst_verdict: str


@dataclass
class BatchResult:
    started_at: str
    finished_at: str
    summary: BatchSummary
    results: list[EndpointResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def scan_endpoint(
    ep: Endpoint, protocol: str, pq_probe: bool, openssl: str | None
) -> EndpointResult:
    if protocol == "ssh":
        scan = scan_ssh(ep.host, ep.port)
        report = grade_ssh(scan) if scan.status == "completed" else None
    else:
        scan = scan_tls(
            ep.host,
            ep.port,
            pq_probe=pq_probe,
            pq_groups=load_rules()["key_exchange"]["pq_probe_groups"],
            openssl=openssl,
        )
        report = grade(scan) if scan.status == "completed" else None
    return EndpointResult(ep.host, ep.port, protocol, scan, report)


def summarize(requested: int, open_count: int, results: list[EndpointResult]) -> BatchSummary:
    graded = [r.grade for r in results if r.grade]
    verdicts = {s: sum(g.verdict == s for g in graded) for s in STATUS_ORDER}
    deadlines = [g.earliest_deadline for g in graded if g.earliest_deadline]
    worst = next((s for s in STATUS_ORDER if verdicts[s]), "unknown")
    return BatchSummary(
        endpoints_requested=requested,
        endpoints_open=open_count,
        scanned=len(graded),
        errors=len(results) - len(graded),
        verdicts=verdicts,
        pq_key_exchange=sum(g.pq_key_exchange for g in graded),
        hndl_exposed=sum(g.hndl_exposed for g in graded),
        earliest_deadline=min(deadlines) if deadlines else None,
        worst_verdict=worst,
    )


def run_batch(
    endpoints: list[Endpoint],
    *,
    forced_protocol: str | None = None,
    workers: int = 4,
    discovery_workers: int = 64,
    pq_probe: bool = True,
    openssl: str | None = None,
) -> BatchResult:
    """Discover open endpoints, scan each with the right protocol, and summarize."""
    started = datetime.now(UTC).isoformat()
    found = discover(endpoints, workers=discovery_workers)
    if forced_protocol:
        found = [(ep, forced_protocol) for ep, _ in found]

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(
            pool.map(lambda item: scan_endpoint(item[0], item[1], pq_probe, openssl), found)
        )
    results.sort(key=lambda r: (_sort_key(r.host), r.port))

    return BatchResult(
        started_at=started,
        finished_at=datetime.now(UTC).isoformat(),
        summary=summarize(len(endpoints), len(found), results),
        results=results,
    )


def _sort_key(host: str) -> tuple:
    """Sort IPs numerically (192.168.1.9 before 192.168.1.10), hostnames after."""
    try:
        return (0, tuple(int(p) for p in host.split(".")))
    except ValueError:
        return (1, host)
