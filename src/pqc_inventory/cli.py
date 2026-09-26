"""Command-line entry point."""

from __future__ import annotations

import argparse
import json
import sys
import warnings

from pqc_inventory import __version__
from pqc_inventory.scanners import scan_tls

# sslyze's bundled trust store contains a legacy root with a non-positive serial number,
# which makes cryptography emit a deprecation warning on every run. It's noise for users.
warnings.filterwarnings("ignore", message="Parsed a serial number which wasn't positive")


def parse_target(target: str) -> tuple[str, int]:
    """Accept 'host' or 'host:port' (IPv6 as '[::1]:443')."""
    if target.startswith("["):
        host, _, rest = target[1:].partition("]")
        return host, int(rest.lstrip(":") or 443)
    if target.count(":") == 1:
        host, port = target.split(":")
        return host, int(port)
    return target, 443


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pqc-inventory",
        description="Inventory the cryptography a TLS endpoint offers. "
        "Only scan systems you own or are authorized to test.",
    )
    parser.add_argument("target", help="host or host:port (default port 443)")
    parser.add_argument("-o", "--output", help="write JSON to this file instead of stdout")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    host, port = parse_target(args.target)
    result = scan_tls(host, port)
    payload = json.dumps(
        {"tool": "pqc-inventory", "version": __version__, "scan": result.to_dict()}, indent=2
    )

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(payload + "\n")
        print(f"Wrote {args.output}", file=sys.stderr)
    else:
        print(payload)

    return 0 if result.status == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
