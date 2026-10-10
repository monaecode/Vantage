#!/usr/bin/env bash
# setup.sh — create the venv, install deps, run the test suite.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
  python3 -m venv .venv
fi
.venv/bin/pip install -q --upgrade pip
.venv/bin/pip install -q -r requirements.txt

echo "Running tests..."
.venv/bin/python -m pytest -q

echo
echo "Setup complete. Next steps:"
echo "  Start the API + dashboard:  .venv/bin/uvicorn vantage.api:app --port 8000"
echo "  Open the dashboard:         http://127.0.0.1:8000/"
echo "  Headless scan:              .venv/bin/python -m vantage.cli scan --target 127.0.0.1 --scope scope.example.yaml --i-am-authorized"
