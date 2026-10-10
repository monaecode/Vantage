# Vantage

**See what attackers see.** Vantage is a standalone, AI-assisted
vulnerability-assessment tool with its own scanning engine and a web
dashboard. It runs entirely on your machine: Python backend, SQLite
storage, and a Liquid Glass dashboard in your browser.

## What it does

1. **Authorization gate** — nothing runs without a *signed* scope file
   naming the target plus your explicit confirmation. Out-of-scope
   targets are refused before a single packet is sent.
2. **Recon** — quiet DNS forward/reverse resolution, scope-checked.
3. **Port scan** — pure-Python TCP connect scan (no root, no nmap) with
   banner grabbing.
4. **Safe checks** — risky open ports (by port/service only), HTTP
   security headers, TLS certificate basics, service banner
   identification. **No exploitation, no brute forcing, no
   default-credential testing — ever.**
5. **Findings** — severity-ranked (critical → info), deduplicated, each
   marked `confirmed` (observed) or `heuristic` (inferred — verify first).
6. **Store + audit** — SQLite for targets/scans/findings; an append-only
   JSON-lines audit log records every action.

## Quickstart

```bash
bash setup.sh                      # venv, deps, tests
# 1. Copy scope.example.yaml -> scope.yaml, fill in YOUR targets + signature
# 2a. Headless scan:
.venv/bin/python -m vantage.cli scan --target 127.0.0.1 \
    --scope scope.yaml --i-am-authorized
# 2b. API + dashboard:
.venv/bin/uvicorn vantage.api:app --port 8000
#    open http://127.0.0.1:8000/
```

Try it against localhost first — `scope.example.yaml` already covers
`127.0.0.1`.

## Safety model

- **Two-key rule:** `--i-am-authorized` (CLI) or `authorized: true`
  (API) **and** a signed scope file (`signed_by`, `signed_date`,
  `statement`). Either missing → the run is refused.
- **Scope checked per phase:** recon, each port probe, and each check
  assert the target is in scope. Exclusions always win.
- **Observation only:** the checks never exploit, brute-force, or test
  credentials. Heuristic findings say so explicitly.

## Structure

```
vantage/            Python package
  scope.py          signed scopes + authorization gate
  recon.py          DNS resolution, scope-checked
  scanner.py        TCP connect scan + banner grab (pure Python)
  checks.py         safe vuln checks (ports, HTTP headers, TLS, banners)
  findings.py       finding model + severity ranking
  store.py          SQLite persistence
  audit.py          append-only audit log
  engine.py         scan pipeline orchestration
  api.py            FastAPI REST API (+ serves the dashboard)
  cli.py            headless CLI
dashboard/          web UI (Local Sandbox design system, vanilla JS)
  index.html        home / scan detail / new scan views
  styles.css        design tokens -> CSS custom properties
  app.js            fetch-based client
tests/              pytest suite (mocked + localhost integration)
scope.example.yaml  copy me, sign me, scan with me
```

## API

| Method | Path | Notes |
|---|---|---|
| GET | `/api/health` | liveness |
| POST | `/api/targets` | add a target |
| GET | `/api/targets` | list targets |
| POST | `/api/scans` | `{host, scope_yaml, authorized, ports?}` → 202 + scan id (403 unsigned, 400 out of scope) |
| GET | `/api/scans` | list scans |
| GET | `/api/scans/{id}` | scan status |
| GET | `/api/scans/{id}/findings?min_severity=low` | severity-ranked findings |
| GET | `/api/scans/{id}/summary` | severity counts |

## Dashboard

Built on the Local Sandbox design language (Apple-style Liquid Glass):
sentence-case verb-first actions ("Run scan"), at most one prominent
action per screen, severity as word-first badges (hue only in data),
glass toolbar over content, calm motion. `dashboard/styles.css`
translates `tokens.json` into CSS custom properties with light and
dark themes.

## Roadmap

- LLM-assisted finding triage and plain-language remediation drafts
  (findings already carry confidence + evidence for this)
- Scheduled / recurring scans
- PDF/HTML report export
- macOS/iOS native client on the same design system

## License

For authorized security testing and education. Only ever scan targets
you have written permission to test.
