"""CBOM and HTML report tests.

The CBOM is validated against the official CycloneDX 1.6 JSON schema (bundled with
cyclonedx-python-lib, so no network access is needed).
"""

import json

import pytest
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator

from pqc_inventory.batch import EndpointResult, summarize
from pqc_inventory.cli import main
from pqc_inventory.models import (
    CertificateInfo,
    CipherSuiteInfo,
    KeyExchangeInfo,
    ProtocolInfo,
    PublicKeyInfo,
    SshHostKey,
    SshScanResult,
    TlsScanResult,
)
from pqc_inventory.output.cbom import build_cbom
from pqc_inventory.output.html import migration_plan, render_html
from pqc_inventory.policy.engine import grade
from pqc_inventory.policy.ssh import grade_ssh

XSS = '<script>alert("pwned")</script><img src=x onerror=alert(1)>'


def tls_result(host, port, groups, subject="CN=example.test"):
    cert = CertificateInfo(
        subject,
        "CN=Test CA",
        "2026-01-01T00:00:00+00:00",
        "2027-01-01T00:00:00+00:00",
        PublicKeyInfo("EC", 256, "secp256r1"),
        "ecdsa-with-SHA256",
        "sha256",
    )
    scan = TlsScanResult(
        host,
        port,
        "2026-09-26T00:00:00+00:00",
        "completed",
        protocols={
            "TLS 1.3": ProtocolInfo(
                True,
                [
                    CipherSuiteInfo(
                        "TLS_AES_128_GCM_SHA256", 128, KeyExchangeInfo("X25519", 253, None)
                    )
                ],
            ),
            "TLS 1.2": ProtocolInfo(
                True, [CipherSuiteInfo("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", 128, None)]
            ),
        },
        supported_groups=groups,
        certificate_chain=[cert],
    )
    return EndpointResult(host, port, "tls", scan, grade(scan))


def ssh_result(host, port, banner="SSH-2.0-OpenSSH_10.0"):
    scan = SshScanResult(
        host,
        port,
        "2026-09-26T00:00:00+00:00",
        "completed",
        banner=banner,
        kex=["mlkem768x25519-sha256", "curve25519-sha256", "kex-strict-s-v00@openssh.com"],
        host_key_algorithms=["ssh-ed25519", "rsa-sha2-512"],
        ciphers=["chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com", "aes256-ctr"],
        macs=["hmac-sha2-256-etm@openssh.com", "hmac-sha1"],
        host_keys=[SshHostKey("ssh-rsa", PublicKeyInfo("RSA", 3072))],
    )
    return EndpointResult(host, port, "ssh", scan, grade_ssh(scan))


@pytest.fixture
def results():
    return [
        tls_result("10.0.0.5", 443, ["X25519", "X25519MLKEM768"]),  # PQ-capable
        tls_result("10.0.0.6", 443, ["X25519"]),  # classical only
        ssh_result("10.0.0.7", 22),
    ]


# --- CBOM -------------------------------------------------------------------------------


def test_cbom_validates_against_official_cyclonedx_1_6_schema(results):
    bom = build_cbom(results)
    error = JsonStrictValidator(SchemaVersion.V1_6).validate_str(json.dumps(bom))
    assert error is None, error


def test_cbom_marks_ml_kem_as_nist_level_3_kem(results):
    comps = {c["name"]: c for c in build_cbom(results)["components"]}
    mlkem = comps["mlkem768x25519-sha256"]["cryptoProperties"]["algorithmProperties"]
    assert mlkem["primitive"] == "kem"
    assert mlkem["nistQuantumSecurityLevel"] == 3
    x25519 = comps["x25519"]["cryptoProperties"]["algorithmProperties"]
    assert x25519["primitive"] == "key-agree"
    assert x25519["nistQuantumSecurityLevel"] == 0
    assert x25519["classicalSecurityLevel"] == 128


def test_cbom_deduplicates_shared_algorithms(results):
    names = [c["name"] for c in build_cbom(results)["components"]]
    assert names.count("x25519") == 1  # used by both TLS endpoints, listed once


def test_cbom_dependencies_reference_real_components(results):
    bom = build_cbom(results)
    refs = {c["bom-ref"] for c in bom["components"]} | {s["bom-ref"] for s in bom["services"]}
    for dep in bom["dependencies"]:
        assert dep["ref"] in refs
        assert set(dep["dependsOn"]) <= refs


def test_cbom_services_carry_verdicts(results):
    services = {s["name"]: s for s in build_cbom(results)["services"]}
    props = {p["name"]: p["value"] for p in services["10.0.0.6:443"]["properties"]}
    assert props["pqc-inventory:hndl-exposed"] == "true"
    assert services["10.0.0.7:22"]["endpoints"] == ["ssh://10.0.0.7:22"]


def test_cbom_includes_algorithms_that_passed(results):
    """An inventory lists everything, not just problems: aes256-ctr has no finding."""
    comps = {c["name"]: c for c in build_cbom(results)["components"]}
    status = {p["name"]: p["value"] for p in comps["aes256-ctr"]["properties"]}
    assert status["pqc-inventory:status"] == "ok"


# --- HTML -------------------------------------------------------------------------------


def test_hostile_banner_and_subject_are_escaped():
    hostile = [
        ssh_result("10.0.0.9", 22, banner=f"SSH-2.0-{XSS}"),
        tls_result("10.0.0.10", 443, ["X25519"], subject=f"CN={XSS}"),
    ]
    html = render_html(hostile, summarize(2, 2, hostile))
    assert "<script>" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;" in html


def test_report_forbids_scripts_via_csp(results):
    html = render_html(results, summarize(3, 3, results))
    assert "default-src 'none'" in html
    assert "<script" not in html.lower()


def test_migration_plan_separates_fallback_from_sole_option(results):
    plan = migration_plan(results)
    x25519 = [i for g in plan for i in g.items if i.subject == "x25519"]
    assert len(x25519) == 2  # low-severity fallback on .5, medium exposure on .6
    assert {tuple(i.endpoints) for i in x25519} == {("10.0.0.5:443",), ("10.0.0.6:443",)}


def test_migration_plan_is_ordered_by_priority(results):
    priorities = [g.priority for g in migration_plan(results)]
    assert priorities == sorted(priorities)


def test_empty_report_explains_what_to_check():
    html = render_html([], summarize(0, 0, []))
    assert "No endpoints were graded" in html


# --- CLI --------------------------------------------------------------------------------


def test_cli_writes_cbom_and_html_from_one_scan(tmp_path, monkeypatch, capsys):
    r = ssh_result("10.0.0.7", 22)
    monkeypatch.setattr("pqc_inventory.cli.scan_ssh", lambda host, port: r.scan)
    cbom, html = tmp_path / "out.cbom.json", tmp_path / "out.html"
    rc = main(["-p", "ssh", "10.0.0.7", "-f", "text", "--cbom", str(cbom), "--html", str(html)])
    assert rc == 0
    assert JsonStrictValidator(SchemaVersion.V1_6).validate_str(cbom.read_text()) is None
    assert "Post-quantum readiness report" in html.read_text()
