"""Probe whether a server accepts hybrid / pure post-quantum TLS 1.3 key exchange.

sslyze's bundled OpenSSL can't offer ML-KEM groups, so this module shells out to an
OpenSSL 3.5+ binary. For each group it runs a TLS 1.3 handshake that offers *only* that
group: if the server negotiates it, the server supports it; if the server answers with a
handshake_failure alert, it doesn't.

Security notes (see SECURITY.md scope):
  * subprocess is always called with an argument list, never a shell string.
  * hostnames are validated so a target like "-proxy evil:80" can't inject s_client flags.
  * every handshake has a hard timeout; stdin is closed so s_client exits after handshake.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess  # noqa: S404 -- used with fixed argv lists only
from pathlib import Path

from pqc_inventory.models import PqProbeResult

ENV_VAR = "PQC_OPENSSL"
MIN_VERSION = (3, 5)
# Homebrew locations (Apple Silicon, Intel) checked before whatever is on PATH, because
# macOS's /usr/bin/openssl is LibreSSL and can't negotiate ML-KEM.
CANDIDATES = (
    "/opt/homebrew/opt/openssl@3/bin/openssl",
    "/usr/local/opt/openssl@3/bin/openssl",
)

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9_]([A-Za-z0-9_-]{0,62})(\.[A-Za-z0-9_-]{1,63})*\.?$"
)
_VERSION_RE = re.compile(r"^OpenSSL (\d+)\.(\d+)\.(\d+)")
_NEGOTIATED_RE = re.compile(r"^Negotiated TLS1\.3 group:\s*(\S+)", re.MULTILINE)


# --- locating a capable OpenSSL ------------------------------------------------------------


def parse_version(output: str) -> tuple[int, int, int] | None:
    """Return (major, minor, patch) for real OpenSSL; None for LibreSSL or anything else."""
    match = _VERSION_RE.match(output.strip())
    return tuple(int(g) for g in match.groups()) if match else None  # type: ignore[return-value]


def _version_of(binary: str) -> str | None:
    try:
        proc = subprocess.run(  # noqa: S603
            [binary, "version"], capture_output=True, text=True, timeout=5, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = proc.stdout.strip()
    # Keep "OpenSSL 3.5.4" and drop the build date / library suffix.
    match = _VERSION_RE.match(output)
    return match.group(0) if match else (output.split(" (")[0] or None)


def find_openssl(explicit: str | None = None) -> tuple[str | None, str | None, str]:
    """Find an OpenSSL >= 3.5 binary.

    Returns (path, version_string, reason). path is None if nothing suitable was found,
    and reason explains why.
    """
    candidates = [explicit] if explicit else []
    if not explicit:
        if os.environ.get(ENV_VAR):
            candidates.append(os.environ[ENV_VAR])
        candidates += [c for c in CANDIDATES if Path(c).exists()]
        on_path = shutil.which("openssl")
        if on_path:
            candidates.append(on_path)

    seen_versions = []
    for binary in candidates:
        version = _version_of(binary)
        if not version:
            continue
        parsed = parse_version(version)
        if parsed and parsed[:2] >= MIN_VERSION:
            return binary, version, "ok"
        seen_versions.append(f"{binary}: {version}")

    if seen_versions:
        return None, None, "OpenSSL 3.5+ required for ML-KEM; found " + "; ".join(seen_versions)
    return None, None, "no openssl binary found (set PQC_OPENSSL or install openssl@3)"


# --- probing ----------------------------------------------------------------------------


def is_safe_host(host: str) -> bool:
    """Accept only IP literals and syntactically valid hostnames (never a leading '-')."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(_HOSTNAME_RE.match(host))


def _connect_arg(host: str, port: int) -> str:
    try:
        if ipaddress.ip_address(host).version == 6:
            return f"[{host}]:{port}"
    except ValueError:
        pass
    return f"{host}:{port}"


def probe_group(
    openssl: str, host: str, port: int, group: str, timeout: float = 10.0
) -> tuple[str, str | None]:
    """Offer exactly one group. Returns ("accepted" | "rejected" | "error", detail)."""
    argv = [
        openssl,
        "s_client",
        "-connect",
        _connect_arg(host, port),
        "-groups",
        group,
        "-tls1_3",
        "-brief",
    ]
    try:
        ipaddress.ip_address(host)
    except ValueError:
        argv[4:4] = ["-servername", host]  # SNI only for hostnames

    try:
        proc = subprocess.run(  # noqa: S603
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return "error", f"timed out after {timeout:.0f}s"
    except OSError as exc:
        return "error", str(exc)

    output = proc.stdout + proc.stderr
    negotiated = _NEGOTIATED_RE.search(output)
    if proc.returncode == 0 and negotiated:
        if negotiated.group(1).lower() == group.lower():
            return "accepted", None
        return "rejected", f"server negotiated {negotiated.group(1)} instead"
    if "alert handshake failure" in output or "alert number 40" in output:
        return "rejected", None
    if "no suitable" in output.lower() or "unsupported" in output.lower():
        return "rejected", None
    last_line = output.strip().splitlines()[-1] if output.strip() else "no output"
    return "error", last_line[:200]


def probe_pq_groups(
    host: str,
    port: int,
    groups: list[str],
    openssl: str | None = None,
    timeout: float = 10.0,
) -> PqProbeResult:
    if not is_safe_host(host):
        return PqProbeResult("error", reason=f"refusing to probe unsafe host value {host!r}")

    binary, version, reason = find_openssl(openssl)
    if not binary:
        return PqProbeResult("skipped", reason=reason)

    result = PqProbeResult("completed", openssl=version)
    for group in groups:
        outcome, detail = probe_group(binary, host, port, group, timeout)
        if outcome == "accepted":
            result.accepted.append(group)
        elif outcome == "rejected":
            result.rejected.append(group)
        else:
            result.errors[group] = detail or "unknown error"

    if result.errors and not (result.accepted or result.rejected):
        result.status = "error"
        result.reason = "all probes failed; see errors"
    return result
