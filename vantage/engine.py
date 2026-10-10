"""engine.py — the scan pipeline orchestration.

One scan, start to finish:

    authorization gate -> recon -> port scan -> safe checks ->
    findings -> store -> audit

The gate runs twice: once up front (two-key rule) and again inside every
phase, because each phase calls the scope-aware helpers directly.
"""

from __future__ import annotations

from pathlib import Path

from . import checks, recon, scanner
from .audit import AuditLog
from .findings import dedupe_findings, sort_findings
from .scope import Scope, assert_in_scope, require_authorization
from . import store


def run_scan(
    scope: Scope,
    host: str,
    db_path: str | Path,
    audit_path: str | Path,
    confirmed: bool = False,
    ports: list[int] | None = None,
    timeout: float = 1.0,
    scan_id: int | None = None,
) -> int:
    """Run a full assessment of ``host``. Returns the scan id."""
    require_authorization(scope, confirmed)
    assert_in_scope(scope, host)

    audit = AuditLog(audit_path)
    if scan_id is None:
        scan_id = store.create_scan(str(db_path), host, engagement=scope.engagement)
    audit.record("scan.start", target=host, scan_id=scan_id, engagement=scope.engagement)

    try:
        store.set_scan_status(str(db_path), scan_id, "running")

        # Recon (DNS only; scope checked inside)
        host_info = recon.resolve_host(scope, host)
        audit.record("recon.resolve", target=host, scan_id=scan_id,
                     addresses=host_info.addresses)

        # Port scan (scope checked per port inside)
        results = scanner.scan_host(scope, host, ports=ports, timeout=timeout)
        open_ports = [r.port for r in results if r.is_open]
        audit.record("scan.ports", target=host, scan_id=scan_id,
                     open_ports=open_ports, probed=len(results))

        # Safe checks over what the scan actually found
        findings = []
        findings.extend(checks.check_risky_ports(scope, host, open_ports))
        for result in results:
            if not result.is_open:
                continue
            findings.extend(checks.check_banner(scope, host, result.port, result.banner))
            if result.port in scanner.HTTP_LIKE_PORTS:
                findings.extend(checks.check_http_headers(scope, host, result.port))
            if result.port in scanner.TLS_LIKE_PORTS:
                findings.extend(checks.check_tls(scope, host, result.port))

        findings = sort_findings(dedupe_findings(findings))
        for finding in findings:
            finding.scan_id = scan_id
            store.add_finding(str(db_path), finding)

        store.set_scan_status(str(db_path), scan_id, "complete")
        audit.record("scan.complete", target=host, scan_id=scan_id,
                     findings=len(findings))
        return scan_id

    except Exception as exc:  # noqa: BLE001 — the scan row must reflect failure
        store.set_scan_status(str(db_path), scan_id, "failed", error=str(exc))
        audit.record("scan.failed", target=host, scan_id=scan_id, error=str(exc))
        raise
