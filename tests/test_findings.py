"""Tests for the finding model and severity ranking."""

import pytest

from vantage.findings import (
    Finding,
    dedupe_findings,
    filter_min_severity,
    rank_key,
    severity_counts,
    sort_findings,
)


def _finding(title, severity, target="127.0.0.1", port=80):
    return Finding(target=target, port=port, title=title, severity=severity)


def test_severity_rank_order():
    assert rank_key("critical") < rank_key("high") < rank_key("medium")
    assert rank_key("medium") < rank_key("low") < rank_key("info")


def test_bad_severity_rejected():
    with pytest.raises(ValueError):
        _finding("x", "extreme")


def test_sort_most_severe_first():
    findings = [_finding("a", "info"), _finding("b", "critical"), _finding("c", "medium")]
    assert [f.title for f in sort_findings(findings)] == ["b", "c", "a"]


def test_filter_min_severity():
    findings = [_finding("a", "critical"), _finding("b", "high"),
                _finding("c", "medium"), _finding("d", "low")]
    kept = filter_min_severity(findings, "high")
    assert {f.title for f in kept} == {"a", "b"}
    with pytest.raises(ValueError):
        filter_min_severity(findings, "severe")


def test_dedupe():
    findings = [_finding("dup", "high"), _finding("dup", "high"),
                _finding("other", "high", port=443)]
    assert len(dedupe_findings(findings)) == 2


def test_severity_counts():
    findings = [_finding("a", "critical"), _finding("b", "critical"),
                _finding("c", "info")]
    counts = severity_counts(findings)
    assert counts["critical"] == 2
    assert counts["info"] == 1
    assert counts["low"] == 0


def test_confidence_must_be_known():
    with pytest.raises(ValueError):
        Finding(target="h", title="t", severity="low", confidence="maybe")
