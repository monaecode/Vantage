"""Tests for SQLite persistence."""

from vantage import store
from vantage.findings import Finding


def test_target_crud(db_path):
    tid = store.add_target(db_path, "127.0.0.1", ports=[80, 443], label="lab")
    targets = store.list_targets(db_path)
    assert len(targets) == 1
    assert targets[0]["id"] == tid
    assert targets[0]["ports"] == [80, 443]


def test_scan_lifecycle(db_path):
    sid = store.create_scan(db_path, "127.0.0.1", engagement="lab")
    scan = store.get_scan(db_path, sid)
    assert scan["status"] == "queued"
    store.set_scan_status(db_path, sid, "running")
    assert store.get_scan(db_path, sid)["status"] == "running"
    store.set_scan_status(db_path, sid, "complete")
    done = store.get_scan(db_path, sid)
    assert done["status"] == "complete"
    assert done["finished_at"]
    assert store.get_scan(db_path, 9999) is None


def test_findings_roundtrip(db_path):
    sid = store.create_scan(db_path, "127.0.0.1")
    fid = store.add_finding(db_path, Finding(
        scan_id=sid, target="127.0.0.1", port=23, service="telnet",
        title="Telnet exposed", severity="high", confidence="heuristic",
        evidence="connect ok", recommendation="disable",
    ))
    findings = store.get_findings(db_path, sid)
    assert len(findings) == 1
    assert findings[0].id == fid
    assert findings[0].severity == "high"


def test_scan_summary(db_path):
    sid = store.create_scan(db_path, "127.0.0.1")
    store.add_finding(db_path, Finding(scan_id=sid, target="h", title="a", severity="critical"))
    store.add_finding(db_path, Finding(scan_id=sid, target="h", title="b", severity="low"))
    summary = store.scan_summary(db_path, sid)
    assert summary["total"] == 2
    assert summary["severity_counts"]["critical"] == 1
    assert summary["severity_counts"]["low"] == 1
