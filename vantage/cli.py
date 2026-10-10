"""cli.py — headless Vantage scans from the terminal.

Usage:
    python -m vantage.cli scan --target 127.0.0.1 --scope scope.yaml --i-am-authorized
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import engine, store
from .findings import SEVERITIES, filter_min_severity, severity_counts, sort_findings
from .scope import ScopeNotAuthorized, ScopeViolation, load_scope_file

DEFAULT_DB = Path(__file__).resolve().parent.parent / "vantage.db"
DEFAULT_AUDIT = Path(__file__).resolve().parent.parent / "audit.log.jsonl"


def _parse_ports(value: str | None) -> list[int] | None:
    if not value:
        return None
    ports: list[int] = []
    for part in value.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def cmd_scan(args: argparse.Namespace) -> int:
    try:
        scope = load_scope_file(args.scope)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    store.init_db(args.db)
    try:
        scan_id = engine.run_scan(
            scope, args.target, args.db, args.audit,
            confirmed=args.i_am_authorized,
            ports=_parse_ports(args.ports),
            timeout=args.timeout,
        )
    except (ScopeNotAuthorized, ScopeViolation) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 3
    except Exception as exc:  # noqa: BLE001
        print(f"scan failed: {exc}", file=sys.stderr)
        return 1

    findings = sort_findings(store.get_findings(args.db, scan_id))
    if args.min_severity != "info":
        findings = filter_min_severity(findings, args.min_severity)
    counts = severity_counts(findings)

    print(f"scan {scan_id} complete: {args.target}")
    print("severity  " + "  ".join(f"{name}={counts[name]}" for name in SEVERITIES))
    print()
    for finding in findings:
        port = f":{finding.port}" if finding.port else ""
        print(f"[{finding.severity.upper():8}] {finding.target}{port} — {finding.title}")
        if finding.confidence == "heuristic":
            print("           (heuristic: verify before acting)")
    return 0


def cmd_scans(args: argparse.Namespace) -> int:
    store.init_db(args.db)
    for scan in store.list_scans(args.db):
        print(f"{scan['id']:4}  {scan['status']:9}  {scan['target_host']}  "
              f"{scan['started_at'] or ''}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vantage",
        description="Vantage — authorized vulnerability assessment. "
                    "Runs locally; refuses anything outside the signed scope.",
    )
    parser.add_argument("--db", default=str(DEFAULT_DB), help="SQLite database path")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="run a scan against a target")
    scan.add_argument("--target", required=True, help="hostname or IP to assess")
    scan.add_argument("--scope", required=True, help="signed scope YAML file")
    scan.add_argument("--i-am-authorized", action="store_true",
                      help="confirm you hold written authorization to test the target")
    scan.add_argument("--ports", default=None,
                      help="ports to probe, e.g. '22,80,443' or '1-1024'")
    scan.add_argument("--timeout", type=float, default=1.0, help="per-port timeout")
    scan.add_argument("--min-severity", default="info", choices=list(SEVERITIES))
    scan.add_argument("--audit", default=str(DEFAULT_AUDIT), help="audit log path")
    scan.set_defaults(func=cmd_scan)

    scans = sub.add_parser("scans", help="list past scans")
    scans.set_defaults(func=cmd_scans)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
