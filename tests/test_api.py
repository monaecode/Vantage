"""API tests: authorization gates, validation, and the scan flow."""

import os

import pytest

os.environ.setdefault("VANTAGE_DB", "/tmp/vantage-test-unused.db")

from fastapi.testclient import TestClient  # noqa: E402

import vantage.api as api_mod  # noqa: E402
from vantage import store  # noqa: E402
from vantage.findings import Finding  # noqa: E402
from tests.conftest import SIGNED_SCOPE_YAML, UNSIGNED_SCOPE_YAML  # noqa: E402


@pytest.fixture
def client(tmp_path, monkeypatch):
    db = tmp_path / "api.db"
    audit = tmp_path / "audit.jsonl"
    store.init_db(db)
    monkeypatch.setattr(api_mod, "DB_PATH", db)
    monkeypatch.setattr(api_mod, "AUDIT_PATH", audit)
    return TestClient(api_mod.app)


def _scan_body(**overrides):
    body = {
        "host": "127.0.0.1",
        "scope_yaml": SIGNED_SCOPE_YAML,
        "authorized": True,
    }
    body.update(overrides)
    return body


def test_health(client):
    assert client.get("/api/health").json()["status"] == "ok"


def test_target_crud(client):
    r = client.post("/api/targets", json={"host": "127.0.0.1", "label": "lab"})
    assert r.status_code == 201
    targets = client.get("/api/targets").json()
    assert any(t["host"] == "127.0.0.1" for t in targets)


def test_scan_rejects_unsigned_scope(client):
    r = client.post("/api/scans", json=_scan_body(scope_yaml=UNSIGNED_SCOPE_YAML))
    assert r.status_code == 403


def test_scan_rejects_missing_confirmation(client):
    r = client.post("/api/scans", json=_scan_body(authorized=False))
    assert r.status_code == 403


def test_scan_rejects_out_of_scope_target(client):
    r = client.post("/api/scans", json=_scan_body(host="8.8.8.8"))
    assert r.status_code == 400


def test_scan_rejects_bad_yaml(client):
    r = client.post("/api/scans", json=_scan_body(scope_yaml=": not: yaml: :"))
    assert r.status_code == 422


def test_full_scan_flow(client, monkeypatch):
    def fake_background(scan_id, scope_yaml, host, ports):
        from vantage import store as store_mod
        import vantage.api as api

        store_mod.set_scan_status(api.DB_PATH, scan_id, "running")
        store_mod.add_finding(api.DB_PATH, Finding(
            scan_id=scan_id, target=host, port=22,
            title="Service identified: OpenSSH", severity="info"))
        store_mod.set_scan_status(api.DB_PATH, scan_id, "complete")

    monkeypatch.setattr(api_mod, "_run_scan_background", fake_background)
    r = client.post("/api/scans", json=_scan_body())
    assert r.status_code == 202
    scan_id = r.json()["scan_id"]

    scan = client.get(f"/api/scans/{scan_id}").json()
    assert scan["status"] == "complete"

    findings = client.get(f"/api/scans/{scan_id}/findings").json()
    assert len(findings) == 1
    assert findings[0]["title"] == "Service identified: OpenSSH"

    summary = client.get(f"/api/scans/{scan_id}/summary").json()
    assert summary["total"] == 1
    assert summary["severity_counts"]["info"] == 1


def test_findings_severity_filter(client, monkeypatch):
    def fake_background(scan_id, scope_yaml, host, ports):
        from vantage import store as store_mod
        import vantage.api as api

        for sev in ("critical", "low", "info"):
            store_mod.add_finding(api.DB_PATH, Finding(
                scan_id=scan_id, target=host, title=f"f-{sev}", severity=sev))
        store_mod.set_scan_status(api.DB_PATH, scan_id, "complete")

    monkeypatch.setattr(api_mod, "_run_scan_background", fake_background)
    scan_id = client.post("/api/scans", json=_scan_body()).json()["scan_id"]
    got = client.get(f"/api/scans/{scan_id}/findings?min_severity=high").json()
    assert {f["severity"] for f in got} == {"critical"}
    bad = client.get(f"/api/scans/{scan_id}/findings?min_severity=bogus")
    assert bad.status_code == 422


def test_missing_scan_404(client):
    assert client.get("/api/scans/4242").status_code == 404
    assert client.get("/api/scans/4242/findings").status_code == 404
