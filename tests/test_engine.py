"""Engine integration test against a real dummy TCP server on localhost.

No mocks: a thread serves a banner on 127.0.0.1, and the full pipeline
(gate -> recon -> scan -> checks -> store -> audit) runs against it.
"""

import socket
import threading

import pytest

from vantage import engine, store
from vantage.audit import AuditLog
from vantage.scope import ScopeViolation, load_scope_text

BANNER = b"SSH-2.0-OpenSSH_7.4\r\n"


@pytest.fixture
def dummy_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def serve():
        srv.settimeout(0.5)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            with conn:
                try:
                    conn.sendall(BANNER)
                except OSError:
                    pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield port
    stop.set()
    thread.join(timeout=2)
    srv.close()


def _scope_for(port: int):
    return load_scope_text(f"""\
engagement: "engine test"
targets:
  - host: 127.0.0.1
    ports: [{port}]
authorization:
  signed_by: "Test"
  signed_date: "2026-10-10"
  statement: "authorized"
""")


def test_full_pipeline_localhost(dummy_server, db_path, audit_path):
    scope = _scope_for(dummy_server)
    scan_id = engine.run_scan(
        scope, "127.0.0.1", db_path, audit_path,
        confirmed=True, ports=[dummy_server], timeout=2.0,
    )
    scan = store.get_scan(db_path, scan_id)
    assert scan["status"] == "complete"

    findings = store.get_findings(db_path, scan_id)
    titles = [f.title for f in findings]
    # Banner identified + heuristic EOL note for OpenSSH 7.4
    assert any("OpenSSH" in t for t in titles)
    assert any("end-of-life" in t for t in titles)

    log = AuditLog(audit_path).read()
    actions = [e["action"] for e in log]
    assert "scan.start" in actions
    assert "scan.complete" in actions


def test_engine_refuses_out_of_scope(dummy_server, db_path, audit_path):
    scope = _scope_for(dummy_server)
    with pytest.raises(ScopeViolation):
        engine.run_scan(scope, "8.8.8.8", db_path, audit_path, confirmed=True)


def test_engine_refuses_unsigned(dummy_server, db_path, audit_path):
    from vantage.scope import ScopeNotAuthorized

    scope = _scope_for(dummy_server)
    scope.authorization = {}
    with pytest.raises(ScopeNotAuthorized):
        engine.run_scan(scope, "127.0.0.1", db_path, audit_path, confirmed=True)
