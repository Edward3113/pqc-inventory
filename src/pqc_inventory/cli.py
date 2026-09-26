"""Command-line entry point."""

from __future__ import annotations

import argparse
import json
import sys
import warnings

from pqc_inventory import __version__
from pqc_inventory.batch import BatchResult, EndpointResult, run_batch, summarize
from pqc_inventory.models import SshScanResult, TlsScanResult
from pqc_inventory.output.cbom import build_cbom
from pqc_inventory.output.html import render_html
from pqc_inventory.policy import load_rules
from pqc_inventory.policy.engine import STATUS_ORDER, GradeReport, grade
from pqc_inventory.policy.ssh import grade_ssh
from pqc_inventory.scanners import scan_ssh, scan_tls
from pqc_inventory.targets import (
    DEFAULT_MAX_HOSTS,
    TargetError,
    expand_targets,
    parse_ports,
    read_target_file,
    split_host_port,
)

# sslyze's bundled trust store contains a legacy root with a non-positive serial number,
# which makes cryptography emit a deprecation warning on every run. It's noise for users.
warnings.filterwarnings("ignore", message="Parsed a serial number which wasn't positive")

EXIT_OK, EXIT_SCAN_ERROR, EXIT_POLICY_FAIL = 0, 1, 2
DEFAULT_PORTS = {"tls": 443, "ssh": 22}

LABELS = {
    "broken": "BROKEN",
    "weak": "WEAK",
    "quantum_vulnerable": "QUANTUM-VULNERABLE",
    "quantum_ready": "QUANTUM-READY",
}


def parse_target(target: str) -> tuple[str, int | None]:
    """Accept 'host' or 'host:port' (IPv6 as '[::1]:443'). Port is None if omitted."""
    return split_host_port(target)


def _probe_line(scan: TlsScanResult) -> str:
    probe = scan.pq_probe
    if probe is None:
        return "Post-quantum probe: disabled"
    if probe.status == "completed":
        accepted = ", ".join(probe.accepted) if probe.accepted else "none accepted"
        errors = f" ({len(probe.errors)} errored)" if probe.errors else ""
        return f"Post-quantum probe: {accepted}{errors} [{probe.openssl}]"
    return f"Post-quantum probe: {probe.status} — {probe.reason}"


def render_text(scan: TlsScanResult | SshScanResult, report: GradeReport) -> str:
    protocol = "SSH" if isinstance(scan, SshScanResult) else "TLS"
    lines = [
        f"pqc-inventory {__version__} — {scan.host}:{scan.port} ({protocol})",
        f"Verdict: {LABELS.get(report.verdict, report.verdict.upper())}",
        f"Post-quantum key exchange: {'YES' if report.pq_key_exchange else 'no'}",
        f"Harvest-now-decrypt-later exposure: {'YES' if report.hndl_exposed else 'no'}",
        f"Server: {scan.banner}" if protocol == "SSH" else _probe_line(scan),
    ]
    if report.earliest_deadline:
        lines.append(f"Earliest NIST IR 8547 deadline: {report.earliest_deadline}")
    counts = ", ".join(f"{LABELS[s].lower()}: {report.counts[s]}" for s in STATUS_ORDER)
    lines += [f"Findings — {counts}", ""]
    for f in report.findings:
        lines.append(f"[P{f.priority}] {LABELS[f.status]:<19} {f.category:<15} {f.subject}")
        lines.append(f"      {f.detail}")
    return "\n".join(lines)


def render_batch_text(batch: BatchResult) -> str:
    s = batch.summary
    lines = [
        f"pqc-inventory {__version__} — batch scan",
        f"Endpoints: {s.endpoints_requested} checked, {s.endpoints_open} open, "
        f"{s.scanned} graded, {s.errors} failed",
        f"Worst verdict: {LABELS.get(s.worst_verdict, s.worst_verdict.upper())}",
        f"Post-quantum key exchange: {s.pq_key_exchange} of {s.scanned} endpoints",
        f"Harvest-now-decrypt-later exposure: {s.hndl_exposed} of {s.scanned} endpoints",
    ]
    if s.earliest_deadline:
        lines.append(f"Earliest NIST IR 8547 deadline: {s.earliest_deadline}")
    lines += [
        "",
        f"{'ENDPOINT':<24} {'PROTO':<5} {'VERDICT':<19} {'PQ KEX':<7} {'HNDL':<5} DETAIL",
    ]
    for r in batch.results:
        endpoint = f"{r.host}:{r.port}"
        if r.grade is None:
            lines.append(
                f"{endpoint:<24} {r.protocol:<5} {'ERROR':<19} {'-':<7} {'-':<5} "
                f"{(r.scan.error or '')[:60]}"
            )
            continue
        g = r.grade
        detail = r.scan.banner if isinstance(r.scan, SshScanResult) else ""
        lines.append(
            f"{endpoint:<24} {r.protocol:<5} {LABELS.get(g.verdict, g.verdict):<19} "
            f"{'yes' if g.pq_key_exchange else 'no':<7} {'YES' if g.hndl_exposed else 'no':<5} "
            f"{detail or ''}"
        )
    if not batch.results:
        lines.append("(no open endpoints found)")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pqc-inventory",
        description="Inventory and grade the cryptography TLS and SSH endpoints offer. "
        "Only scan systems you own or are authorized to test.",
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help="hosts, host:port, or CIDR ranges (e.g. 192.168.1.0/24)",
    )
    parser.add_argument("-i", "--input", help="file with one target per line")
    parser.add_argument(
        "-p",
        "--protocol",
        choices=["tls", "ssh"],
        help="force a protocol (default: TLS for single targets, auto-detect for batches)",
    )
    parser.add_argument(
        "--ports", help="ports to check for each host, e.g. 22,443,8443 (batch default: 22,443)"
    )
    parser.add_argument(
        "--workers", type=int, default=4, help="endpoints scanned in parallel (default 4)"
    )
    parser.add_argument(
        "--max-hosts",
        type=int,
        default=DEFAULT_MAX_HOSTS,
        help=f"refuse to expand more hosts than this (default {DEFAULT_MAX_HOSTS})",
    )
    parser.add_argument(
        "--allow-public",
        action="store_true",
        help="allow CIDR ranges outside private address space (only if authorized)",
    )
    parser.add_argument("-o", "--output", help="write output to this file instead of stdout")
    parser.add_argument(
        "-f",
        "--format",
        choices=["json", "text", "cbom", "html"],
        default="json",
        help="output format: raw JSON, terminal text, CycloneDX 1.6 CBOM, or HTML report",
    )
    parser.add_argument("--cbom", metavar="FILE", help="also write a CycloneDX 1.6 CBOM here")
    parser.add_argument("--html", metavar="FILE", help="also write an HTML report here")
    parser.add_argument("--title", help="title for the HTML report")
    parser.add_argument(
        "--fail-on",
        choices=["broken", "weak", "quantum_vulnerable"],
        help="exit with code 2 if any verdict is this status or worse (for CI gates)",
    )
    parser.add_argument(
        "--no-pq-probe", action="store_true", help="skip the OpenSSL post-quantum group probe"
    )
    parser.add_argument(
        "--openssl", help="path to an OpenSSL 3.5+ binary (default: $PQC_OPENSSL, Homebrew, PATH)"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _emit(payload: str, output: str | None) -> None:
    if output:
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(payload + "\n")
        print(f"Wrote {output}", file=sys.stderr)
        return
    try:
        print(payload)
    except BrokenPipeError:  # e.g. piped into `head`; exit quietly like standard tools
        sys.stderr.close()


def _render_artifact(kind: str, results: list[EndpointResult], title: str | None = None) -> str:
    if kind == "cbom":
        return json.dumps(build_cbom(results), indent=2)
    return render_html(results, summarize(len(results), len(results), results), title)


def _write_extras(args: argparse.Namespace, results: list[EndpointResult]) -> None:
    """--cbom / --html: write additional artifacts from the same scan."""
    for kind, path in (("cbom", args.cbom), ("html", args.html)):
        if path:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(_render_artifact(kind, results, args.title) + "\n")
            print(f"Wrote {path}", file=sys.stderr)


def _fails(verdict: str, threshold: str | None) -> bool:
    return bool(
        threshold
        and verdict in STATUS_ORDER
        and STATUS_ORDER.index(verdict) <= STATUS_ORDER.index(threshold)
    )


def run_single(args: argparse.Namespace, spec: str) -> int:
    protocol = args.protocol or "tls"
    host, port = parse_target(spec)
    port = port or DEFAULT_PORTS[protocol]
    if protocol == "ssh":
        scan = scan_ssh(host, port)
        report = grade_ssh(scan) if scan.status == "completed" else None
    else:
        scan = scan_tls(
            host,
            port,
            pq_probe=not args.no_pq_probe,
            pq_groups=load_rules()["key_exchange"]["pq_probe_groups"],
            openssl=args.openssl,
        )
        report = grade(scan) if scan.status == "completed" else None

    results = [EndpointResult(host, port, protocol, scan, report)]
    if args.format == "text":
        payload = render_text(scan, report) if report else f"Scan failed: {scan.error}"
    elif args.format in ("cbom", "html"):
        payload = _render_artifact(args.format, results, args.title)
    else:
        payload = json.dumps(
            {
                "tool": "pqc-inventory",
                "version": __version__,
                "protocol": protocol,
                "scan": scan.to_dict(),
                "grade": report.to_dict() if report else None,
            },
            indent=2,
        )
    _emit(payload, args.output)
    _write_extras(args, results)

    if report is None:
        return EXIT_SCAN_ERROR
    return EXIT_POLICY_FAIL if _fails(report.verdict, args.fail_on) else EXIT_OK


def run_many(args: argparse.Namespace, specs: list[str]) -> int:
    ports = parse_ports(args.ports) if args.ports else None
    endpoints = expand_targets(specs, ports, args.allow_public, args.max_hosts)
    print(f"Checking {len(endpoints)} endpoints...", file=sys.stderr)
    batch = run_batch(
        endpoints,
        forced_protocol=args.protocol,
        workers=args.workers,
        pq_probe=not args.no_pq_probe,
        openssl=args.openssl,
    )
    if args.format == "text":
        payload = render_batch_text(batch)
    elif args.format in ("cbom", "html"):
        payload = _render_artifact(args.format, batch.results, args.title)
    else:
        payload = json.dumps(
            {"tool": "pqc-inventory", "version": __version__, "batch": batch.to_dict()},
            indent=2,
        )
    _emit(payload, args.output)
    _write_extras(args, batch.results)
    return EXIT_POLICY_FAIL if _fails(batch.summary.worst_verdict, args.fail_on) else EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    specs = list(args.targets)
    try:
        if args.input:
            specs += read_target_file(args.input)
    except OSError as exc:
        parser.error(f"cannot read {args.input}: {exc}")
    if not specs:
        parser.error("no targets given")

    single = len(specs) == 1 and "/" not in specs[0] and not args.ports and not args.input
    try:
        return run_single(args, specs[0]) if single else run_many(args, specs)
    except TargetError as exc:
        parser.error(str(exc))
        return EXIT_SCAN_ERROR  # unreachable; parser.error exits


if __name__ == "__main__":
    raise SystemExit(main())
