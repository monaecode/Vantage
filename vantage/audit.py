"""audit.py — append-only audit log.

Every scan action is recorded as one JSON object per line: timestamp,
action, target, and free-form detail. The file is only ever appended to;
nothing in Vantage edits or deletes audit entries.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


class AuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, action: str, target: str | None = None, **detail) -> dict:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "target": target,
            **detail,
        }
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
        return entry

    def read(self, limit: int | None = None) -> list[dict]:
        if not self.path.exists():
            return []
        entries = [
            json.loads(line)
            for line in self.path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        return entries[-limit:] if limit else entries
