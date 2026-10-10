"""store.py — SQLite persistence for targets, scans, and findings."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .findings import Finding, severity_counts

SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL,
    ports TEXT,
    label TEXT DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_host TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    engagement TEXT DEFAULT '',
    started_at TEXT,
    finished_at TEXT,
    error TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    target TEXT NOT NULL,
    port INTEGER,
    service TEXT DEFAULT '',
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL DEFAULT 'confirmed',
    evidence TEXT DEFAULT '',
    recommendation TEXT DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def connect(db_path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str | Path) -> None:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with connect(db_path) as conn:
        conn.executescript(SCHEMA)


# -- targets ---------------------------------------------------------------

def add_target(db_path: str | Path, host: str, ports: list[int] | None = None,
               label: str = "") -> int:
    with connect(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO targets (host, ports, label, created_at) VALUES (?, ?, ?, ?)",
            (host, json.dumps(ports) if ports else None, label, _now()),
        )
        return cur.lastrowid


def list_targets(db_path: str | Path) -> list[dict]:
    with connect(db_path) as conn:
        rows = conn.execute("SELECT * FROM targets ORDER BY id DESC").fetchall()
    return [dict(r) | {"ports": json.loads(r["ports"]) if r["ports"] else None} for r in rows]


# -- scans -----------------------------------------------------------------

def create_scan(db_path: str | Path, target_host: str, engagement: str = "") -> int:
    with connect(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO scans (target_host, status, engagement, started_at) "
            "VALUES (?, 'queued', ?, ?)",
            (target_host, engagement, _now()),
        )
        return cur.lastrowid


def set_scan_status(db_path: str | Path, scan_id: int, status: str,
                    error: str = "") -> None:
    finished = _now() if status in ("complete", "failed") else None
    with connect(db_path) as conn:
        if finished:
            conn.execute(
                "UPDATE scans SET status=?, finished_at=?, error=? WHERE id=?",
                (status, finished, error, scan_id),
            )
        else:
            conn.execute("UPDATE scans SET status=? WHERE id=?", (status, scan_id))


def get_scan(db_path: str | Path, scan_id: int) -> dict | None:
    with connect(db_path) as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    return dict(row) if row else None


def list_scans(db_path: str | Path) -> list[dict]:
    with connect(db_path) as conn:
        rows = conn.execute("SELECT * FROM scans ORDER BY id DESC").fetchall()
    return [dict(r) for r in rows]


# -- findings --------------------------------------------------------------

def add_finding(db_path: str | Path, finding: Finding) -> int:
    with connect(db_path) as conn:
        cur = conn.execute(
            """INSERT INTO findings
               (scan_id, target, port, service, title, description, severity,
                confidence, evidence, recommendation, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (finding.scan_id, finding.target, finding.port, finding.service,
             finding.title, finding.description, finding.severity,
             finding.confidence, finding.evidence, finding.recommendation,
             finding.created_at),
        )
        return cur.lastrowid


def get_findings(db_path: str | Path, scan_id: int) -> list[Finding]:
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM findings WHERE scan_id=? ORDER BY id", (scan_id,)
        ).fetchall()
    findings = []
    for r in rows:
        d = dict(r)
        findings.append(Finding(
            id=d["id"], scan_id=d["scan_id"], target=d["target"], port=d["port"],
            service=d["service"], title=d["title"], description=d["description"],
            severity=d["severity"], confidence=d["confidence"], evidence=d["evidence"],
            recommendation=d["recommendation"], created_at=d["created_at"],
        ))
    return findings


def scan_summary(db_path: str | Path, scan_id: int) -> dict:
    scan = get_scan(db_path, scan_id) or {}
    findings = get_findings(db_path, scan_id)
    return {
        "scan": scan,
        "total": len(findings),
        "severity_counts": severity_counts(findings),
    }
