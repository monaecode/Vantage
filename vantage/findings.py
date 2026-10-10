"""findings.py — the finding data model and severity ranking.

Severities, highest first: critical, high, medium, low, info.
Each finding also carries a confidence level:

* ``confirmed``  — directly observed (e.g. a missing security header).
* ``heuristic``  — inferred from a banner or pattern; treat as a lead,
  not proof. Heuristic findings say so in their description.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"
INFO = "info"

SEVERITIES = (CRITICAL, HIGH, MEDIUM, LOW, INFO)
_SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}

CONFIRMED = "confirmed"
HEURISTIC = "heuristic"


def normalize_severity(value: str) -> str:
    value = (value or "").strip().lower()
    if value not in _SEVERITY_RANK:
        raise ValueError(f"unknown severity {value!r}; expected one of {SEVERITIES}")
    return value


def rank_key(severity: str) -> int:
    """Lower number = more severe. Suitable as a sort key."""
    return _SEVERITY_RANK[normalize_severity(severity)]


@dataclass
class Finding:
    target: str
    title: str
    severity: str
    description: str = ""
    port: int | None = None
    service: str = ""
    confidence: str = CONFIRMED
    evidence: str = ""
    recommendation: str = ""
    scan_id: int | None = None
    id: int | None = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self) -> None:
        self.severity = normalize_severity(self.severity)
        if self.confidence not in (CONFIRMED, HEURISTIC):
            raise ValueError(f"unknown confidence {self.confidence!r}")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "target": self.target,
            "port": self.port,
            "service": self.service,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Most severe first; ties broken by target, then port, then title."""
    return sorted(
        findings,
        key=lambda f: (rank_key(f.severity), f.target, f.port or 0, f.title),
    )


def filter_min_severity(findings: list[Finding], minimum: str) -> list[Finding]:
    """Keep findings at or above ``minimum`` severity (e.g. 'high')."""
    threshold = rank_key(minimum)
    return [f for f in findings if rank_key(f.severity) <= threshold]


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Drop exact duplicates on (target, port, title), keeping the first."""
    seen: set[tuple] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.target, finding.port, finding.title)
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {name: 0 for name in SEVERITIES}
    for finding in findings:
        counts[finding.severity] += 1
    return counts
