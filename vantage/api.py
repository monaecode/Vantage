"""api.py — FastAPI REST API for Vantage.

Endpoints are grouped under /api; the web dashboard is served from /.

The scan endpoint enforces the same two-key authorization gate as the CLI:
the request must carry ``authorized: true`` AND a signed scope YAML that
covers the target. Unsigned scopes get 403; out-of-scope targets get 400.
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import yaml

from . import engine, store
from .findings import filter_min_severity, sort_findings
from .scope import (
    ScopeNotAuthorized,
    ScopeViolation,
    load_scope_text,
    require_authorization,
    assert_in_scope,
)

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.environ.get("VANTAGE_DB", BASE_DIR / "vantage.db"))
AUDIT_PATH = Path(os.environ.get("VANTAGE_AUDIT", BASE_DIR / "audit.log.jsonl"))
DASHBOARD_DIR = BASE_DIR / "dashboard"

store.init_db(DB_PATH)

app = FastAPI(title="Vantage", version="0.1.0")


@app.exception_handler(ScopeViolation)
async def _scope_violation_handler(_request, exc: ScopeViolation):
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.exception_handler(ScopeNotAuthorized)
async def _not_authorized_handler(_request, exc: ScopeNotAuthorized):
    return JSONResponse(status_code=403, content={"detail": str(exc)})


class TargetIn(BaseModel):
    host: str = Field(min_length=1, max_length=255)
    ports: list[int] | None = None
    label: str = ""


class ScanIn(BaseModel):
    host: str = Field(min_length=1, max_length=255)
    scope_yaml: str = Field(min_length=1)
    authorized: bool = False
    ports: list[int] | None = None


def _parse_and_gate(payload: ScanIn):
    """Parse the scope YAML and enforce the two-key gate. Raises 400/403."""
    try:
        scope = load_scope_text(payload.scope_yaml)
    except (ValueError, FileNotFoundError, yaml.YAMLError) as exc:
        raise HTTPException(status_code=422, detail=f"invalid scope file: {exc}")
    require_authorization(scope, payload.authorized)   # 403 on failure
    assert_in_scope(scope, payload.host)               # 400 on failure
    return scope


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "vantage"}


@app.post("/api/targets", status_code=201)
def create_target(body: TargetIn):
    target_id = store.add_target(DB_PATH, body.host.strip(), body.ports, body.label)
    return {"id": target_id, "host": body.host.strip()}


@app.get("/api/targets")
def get_targets():
    return store.list_targets(DB_PATH)


def _run_scan_background(scan_id: int, scope_yaml: str, host: str,
                         ports: list[int] | None):
    scope = load_scope_text(scope_yaml)
    engine.run_scan(scope, host, DB_PATH, AUDIT_PATH,
                    confirmed=True, ports=ports, scan_id=scan_id)


@app.post("/api/scans", status_code=202)
def start_scan(body: ScanIn, background: BackgroundTasks):
    scope = _parse_and_gate(body)
    scan_id = store.create_scan(DB_PATH, body.host.strip(),
                                engagement=scope.engagement)
    background.add_task(_run_scan_background, scan_id, body.scope_yaml,
                        body.host.strip(), body.ports)
    return {"scan_id": scan_id, "status": "queued"}


@app.get("/api/scans")
def get_scans():
    return store.list_scans(DB_PATH)


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: int):
    scan = store.get_scan(DB_PATH, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")
    return scan


@app.get("/api/scans/{scan_id}/findings")
def get_findings(scan_id: int, min_severity: str = "info"):
    if not store.get_scan(DB_PATH, scan_id):
        raise HTTPException(status_code=404, detail="scan not found")
    findings = sort_findings(store.get_findings(DB_PATH, scan_id))
    try:
        findings = filter_min_severity(findings, min_severity)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return [f.to_dict() for f in findings]


@app.get("/api/scans/{scan_id}/summary")
def get_summary(scan_id: int):
    if not store.get_scan(DB_PATH, scan_id):
        raise HTTPException(status_code=404, detail="scan not found")
    return store.scan_summary(DB_PATH, scan_id)


if DASHBOARD_DIR.exists():
    app.mount("/", StaticFiles(directory=DASHBOARD_DIR, html=True), name="dashboard")
