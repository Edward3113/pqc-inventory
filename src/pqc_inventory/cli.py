"""Command-line entry point."""

from __future__ import annotations

import argparse
import json
import sys
import warnings

from pqc_inventory import __version__
from pqc_inventory.policy.engine import STATUS_ORDER, GradeReport, grade
from pqc_inventory.scanners import scan_tls

# sslyze's bundled trust store contains a legacy root with a non-positive serial number,
# which makes cryptography emit a deprecation warning on every run. It's noise for users.
warnings.filterwarnings("ignore", message="Parsed a serial number which wasn't positive")

EXIT_OK, EXIT_SCAN_ERROR, EXIT_POLICY_FAIL = 0, 1, 2

LABELS = {
    "broken": "BROKEN",
    "weak": "WEAK",
    "quantum_vulnerable": "QUANTUM-VULNERABLE",
    "quantum_ready": "QUANTUM-READY",
}


def parse_target(target: str) -> tuple[str, int]:
    """Accept 'host' or 'host:port' (IPv6 as '[::1]:443')."""
    if target.startswith("["):
        host, _, rest = target[1:].partition("]")
        return host, int(rest.lstrip(":") or 443)
    if target.count(":") == 1:
        host, port = target.split(":")
        return host, int(port)
    return target, 443


def render_text(host: str, port: int, report: GradeReport) -> str:
    lines = [
        f"pqc-inventory {__version__} — {host}:{port}",
        f"Verdict: {LABELS.get(report.verdict, report.verdict.upper())}",
        f"Harvest-now-decrypt-later exposure: {'YES' if report.hndl_exposed else 'no'}",
    ]
    if report.earliest_deadline:
        lines.append(f"Earliest NIST IR 8547 deadline: {report.earliest_deadline}")
    counts = ", ".join(f"{LABELS[s].lower()}: {report.counts[s]}" for s in STATUS_ORDER)
    lines += [f"Findings — {counts}", ""]
    for f in report.findings:
        lines.append(f"[P{f.priority}] {LABELS[f.status]:<19} {f.category:<15} {f.subject}")
        lines.append(f"      {f.detail}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pqc-inventory",
        description="Inventory and grade the cryptography a TLS endpoint offers. "
        "Only scan systems you own or are authorized to test.",
    )
    parser.add_argument("target", help="host or host:port (default port 443)")
    parser.add_argument("-o", "--output", help="write output to this file instead of stdout")
    parser.add_argument(
        "-f", "--format", choices=["json", "text"], default="json", help="output format"
    )
    parser.add_argument(
        "--fail-on",
        choices=["broken", "weak", "quantum_vulnerable"],
        help="exit with code 2 if the verdict is this status or worse (for CI gates)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    host, port = parse_target(args.target)
    scan = scan_tls(host, port)
    report = grade(scan) if scan.status == "completed" else None

    if args.format == "text":
        payload = render_text(host, port, report) if report else f"Scan failed: {scan.error}"
    else:
        payload = json.dumps(
            {
                "tool": "pqc-inventory",
                "version": __version__,
                "scan": scan.to_dict(),
                "grade": report.to_dict() if report else None,
            },
            indent=2,
        )

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(payload + "\n")
        print(f"Wrote {args.output}", file=sys.stderr)
    else:
        print(payload)

    if report is None:
        return EXIT_SCAN_ERROR
    if args.fail_on and report.verdict in STATUS_ORDER:
        if STATUS_ORDER.index(report.verdict) <= STATUS_ORDER.index(args.fail_on):
            return EXIT_POLICY_FAIL
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
