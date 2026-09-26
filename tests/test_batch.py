"""Range scanning: target expansion, discovery, and the batch pipeline."""

import json
import socket
import struct
import threading

import pytest

from pqc_inventory.batch import run_batch
from pqc_inventory.cli import main
from pqc_inventory.discovery import detect, discover
from pqc_inventory.targets import (
    Endpoint,
    TargetError,
    expand_targets,
    parse_ports,
    read_target_file,
)

# --- target expansion --------------------------------------------------------------------


def test_cidr_expands_to_usable_hosts():
    eps = expand_targets(["192.168.1.0/30"], [22])
    assert [e.host for e in eps] == ["192.168.1.1", "192.168.1.2"]


def test_home_network_24_is_254_hosts_times_ports():
    assert len(expand_targets(["192.168.1.0/24"], [22, 443])) == 254 * 2


def test_public_range_refused_without_flag():
    with pytest.raises(TargetError, match="not private"):
        expand_targets(["8.8.8.0/30"])
    assert len(expand_targets(["8.8.8.0/30"], [443], allow_public=True)) == 2


def test_max_hosts_enforced():
    with pytest.raises(TargetError, match="limit"):
        expand_targets(["10.0.0.0/16"])


def test_explicit_port_overrides_port_list_and_dedupes():
    eps = expand_targets(["host.local:8443", "host.local", "host.local"], [22, 443])
    assert [(e.host, e.port, e.explicit_port) for e in eps] == [
        ("host.local", 8443, True),
        ("host.local", 22, False),
        ("host.local", 443, False),
    ]


@pytest.mark.parametrize(
    ("text", "expected"),
    [("22,443", [22, 443]), ("8000-8002", [8000, 8001, 8002]), ("22, 22 ,443", [22, 443])],
)
def test_parse_ports(text, expected):
    assert parse_ports(text) == expected


@pytest.mark.parametrize("bad", ["0", "70000", "10-5"])
def test_parse_ports_rejects_bad_values(bad):
    with pytest.raises(TargetError):
        parse_ports(bad)


def test_target_file_skips_comments_and_blanks(tmp_path):
    f = tmp_path / "targets.txt"
    f.write_text("# home lab\nstart9.local:22\n\n192.168.1.0/30  # router subnet\n")
    assert read_target_file(str(f)) == ["start9.local:22", "192.168.1.0/30"]


# --- fake servers ------------------------------------------------------------------------


def _name_list(items):
    raw = ",".join(items).encode()
    return struct.pack(">I", len(raw)) + raw


def _kexinit_packet():
    lists = [
        ["sntrup761x25519-sha512@openssh.com", "curve25519-sha256", "kex-strict-s-v00@openssh.com"],
        ["ssh-ed25519"],
        ["aes128-ctr"],
        ["aes128-ctr"],
        ["hmac-sha2-256"],
        ["hmac-sha2-256"],
        ["none"],
        ["none"],
        [],
        [],
    ]
    payload = bytes([20]) + b"\x00" * 16 + b"".join(_name_list(x) for x in lists) + b"\x00" * 5
    body = bytes([4]) + payload + b"\x00" * 4
    return struct.pack(">I", len(body)) + body


class MultiServer:
    """Accepts any number of connections; 'ssh' sends a banner + KEXINIT, 'silent' waits."""

    def __init__(self, kind):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.kind = kind
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        with conn:
            try:
                if self.kind == "ssh":
                    conn.sendall(b"SSH-2.0-FakeSSH_1.0\r\n" + _kexinit_packet())
                conn.settimeout(3)
                conn.recv(1024)
            except OSError:
                pass

    def close(self):
        self.sock.close()


@pytest.fixture
def servers():
    made = []

    def make(kind):
        s = MultiServer(kind)
        made.append(s)
        return s

    yield make
    for s in made:
        s.close()


def _closed_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# --- discovery ---------------------------------------------------------------------------


def test_detect_classifies_ssh_silent_and_closed(servers):
    ssh, silent = servers("ssh"), servers("silent")
    assert detect("127.0.0.1", ssh.port) == "ssh"
    assert detect("127.0.0.1", silent.port, banner_wait=0.3) == "tls"
    assert detect("127.0.0.1", _closed_port()) is None


def test_discover_returns_only_open_endpoints(servers):
    ssh = servers("ssh")
    eps = [Endpoint("127.0.0.1", ssh.port, False), Endpoint("127.0.0.1", _closed_port(), False)]
    found = discover(eps)
    assert [(e.port, proto) for e, proto in found] == [(ssh.port, "ssh")]


# --- batch pipeline ----------------------------------------------------------------------


def test_batch_scans_and_summarizes(servers):
    a, b = servers("ssh"), servers("ssh")
    eps = expand_targets(["127.0.0.1"], [a.port, b.port, _closed_port()])
    batch = run_batch(eps)
    s = batch.summary
    assert (s.endpoints_requested, s.endpoints_open, s.scanned, s.errors) == (3, 2, 2, 0)
    assert s.pq_key_exchange == 2
    assert s.hndl_exposed == 0
    assert all(r.protocol == "ssh" for r in batch.results)


def test_cli_batch_json_and_fail_on(servers, capsys):
    ssh = servers("ssh")
    rc = main(["127.0.0.1", "--ports", str(ssh.port), "--fail-on", "quantum_vulnerable"])
    out = json.loads(capsys.readouterr().out)
    assert out["batch"]["summary"]["scanned"] == 1
    assert out["batch"]["results"][0]["protocol"] == "ssh"
    assert rc == 2  # host keys are classical, so quantum_vulnerable threshold trips


def test_cli_refuses_public_range(capsys):
    with pytest.raises(SystemExit):
        main(["1.1.1.0/30"])
    assert "not private" in capsys.readouterr().err
