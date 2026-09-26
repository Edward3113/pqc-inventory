"""Self-contained HTML report.

Everything shown comes from servers that may be hostile (SSH banners, certificate subjects),
so Jinja2 autoescaping is always on and the page carries a Content-Security-Policy that
forbids scripts entirely. The file has no external dependencies and can be emailed as-is.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime

from jinja2 import Environment, PackageLoader, select_autoescape

from pqc_inventory import __version__
from pqc_inventory.batch import BatchSummary, EndpointResult
from pqc_inventory.models import SshScanResult

PRIORITY_TITLES = {
    1: ("Fix now", "Broken today, regardless of quantum computing."),
    2: ("Fix soon", "Discouraged configurations that weaken security today."),
    3: (
        "Migrate key exchange",
        "Recorded traffic can be decrypted once quantum computers arrive (harvest now, "
        "decrypt later). Enable hybrid post-quantum key exchange.",
    ),
    4: (
        "Plan signature migration",
        "Certificates and host keys only need to resist forgery at connection time; migrate "
        "to post-quantum signatures as they become available.",
    ),
    5: ("Quantum-ready", "Already protected. Keep these enabled."),
}
STATUS_LABELS = {
    "broken": "Broken",
    "weak": "Weak",
    "quantum_vulnerable": "Quantum-vulnerable",
    "quantum_ready": "Quantum-ready",
    "unknown": "Unknown",
}


@dataclass
class PlanItem:
    category: str
    subject: str
    status: str
    detail: str
    deadline: str | None
    endpoints: list[str] = field(default_factory=list)


@dataclass
class PlanGroup:
    priority: int
    title: str
    description: str
    items: list[PlanItem]


def migration_plan(results: list[EndpointResult]) -> list[PlanGroup]:
    """Group identical findings across endpoints, ordered by priority."""
    grouped: dict[tuple[int, str, str, str], PlanItem] = {}
    for r in results:
        if not r.grade:
            continue
        for f in r.grade.findings:
            # Severity is part of the key: x25519 as a fallback beside ML-KEM is a different
            # situation from x25519 as a server's only option.
            key = (f.priority, f.status, f.severity, f.category, f.subject)
            if key not in grouped:
                deadline = None
                if f.nist and (f.nist.deprecated_after or f.nist.disallowed_after):
                    deadline = (
                        f"deprecated after {f.nist.deprecated_after}"
                        if f.nist.deprecated_after
                        else f"disallowed after {f.nist.disallowed_after}"
                    )
                detail = f.detail.split(" NIST IR 8547:")[0]  # deadline has its own column
                grouped[key] = PlanItem(f.category, f.subject, f.status, detail, deadline)
            endpoint = f"{r.host}:{r.port}"
            if endpoint not in grouped[key].endpoints:
                grouped[key].endpoints.append(endpoint)

    by_priority: dict[int, list[PlanItem]] = defaultdict(list)
    for (priority, *_), item in sorted(grouped.items(), key=lambda kv: kv[0]):
        by_priority[priority].append(item)
    return [
        PlanGroup(p, *PRIORITY_TITLES[p], sorted(items, key=lambda i: -len(i.endpoints)))
        for p, items in sorted(by_priority.items())
    ]


def timeline_counts(results: list[EndpointResult]) -> dict[str, int]:
    """Distinct findings (per endpoint) landing on each NIST IR 8547 deadline."""
    deprecated, disallowed = 0, 0
    for r in results:
        if not r.grade:
            continue
        for f in r.grade.findings:
            if f.nist and f.nist.deprecated_after == 2030:
                deprecated += 1
            if f.nist and f.nist.disallowed_after == 2035:
                disallowed += 1
    return {"deprecated_2030": deprecated, "disallowed_2035": disallowed}


def render_html(results: list[EndpointResult], summary: BatchSummary) -> str:
    env = Environment(
        loader=PackageLoader("pqc_inventory.output", "templates"),
        autoescape=select_autoescape(default=True, default_for_string=True),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template("report.html.j2")
    return template.render(
        version=__version__,
        generated_at=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        summary=summary,
        results=results,
        plan=migration_plan(results),
        timeline=timeline_counts(results),
        status_labels=STATUS_LABELS,
        is_ssh=lambda scan: isinstance(scan, SshScanResult),
    )
