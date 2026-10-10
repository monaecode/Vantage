"""Tests for the safe vulnerability checks."""

import pytest

from vantage import checks
from vantage.scope import ScopeViolation


def test_risky_ports_flagged(signed_scope):
    findings = checks.check_risky_ports(signed_scope, "127.0.0.1", [23, 80, 6379])
    by_port = {f.port: f for f in findings}
    assert 80 not in by_port  # ordinary web port: no finding
    assert by_port[23].severity == "high"
    assert by_port[6379].severity == "high"
    assert all(f.confidence == "heuristic" for f in findings)


def test_risky_ports_out_of_scope_refused(signed_scope):
    with pytest.raises(ScopeViolation):
        checks.check_risky_ports(signed_scope, "8.8.8.8", [23])


class FakeResponse:
    def __init__(self, headers):
        self._headers = headers

    def getheaders(self):
        return list(self._headers.items())

    def read(self):
        return b""


class FakeHTTPConnection:
    headers = {}

    def __init__(self, host, port, timeout=None):
        pass

    def request(self, method, path, headers=None):
        pass

    def getresponse(self):
        return FakeResponse(FakeHTTPConnection.headers)

    def close(self):
        pass


@pytest.fixture
def fake_http(monkeypatch):
    monkeypatch.setattr(checks.http.client, "HTTPConnection", FakeHTTPConnection)
    monkeypatch.setattr(checks.http.client, "HTTPSConnection", FakeHTTPConnection)
    return FakeHTTPConnection


def test_missing_security_headers(signed_scope, fake_http):
    fake_http.headers = {"server": "nginx/1.20.0", "content-type": "text/html"}
    findings = checks.check_http_headers(signed_scope, "127.0.0.1", 80)
    titles = [f.title for f in findings]
    assert any("content-security-policy" in t for t in titles)
    assert any("x-frame-options" in t for t in titles)
    # HSTS is skipped for plain HTTP
    assert not any("strict-transport-security" in t for t in titles)
    # Server header disclosure is informational
    server_f = [f for f in findings if "Server header" in f.title][0]
    assert server_f.severity == "info"
    assert all(f.confidence == "confirmed" for f in findings)


def test_hsts_checked_over_tls(signed_scope, fake_http):
    fake_http.headers = {}
    findings = checks.check_http_headers(signed_scope, "127.0.0.1", 443, use_tls=True)
    assert any("strict-transport-security" in f.title for f in findings)


def test_banner_identification():
    service, version = checks.identify_service("SSH-2.0-OpenSSH_8.9p1 Ubuntu")
    assert service == "OpenSSH"
    assert version.startswith("8.9")


def test_eol_banner_flagged_as_heuristic(signed_scope):
    findings = checks.check_banner(signed_scope, "127.0.0.1", 22, "SSH-2.0-OpenSSH_7.4\r\n")
    eol = [f for f in findings if "end-of-life" in f.title]
    assert len(eol) == 1
    assert eol[0].severity == "medium"
    assert eol[0].confidence == "heuristic"


def test_current_banner_not_flagged(signed_scope):
    findings = checks.check_banner(signed_scope, "127.0.0.1", 22, "SSH-2.0-OpenSSH_9.6\r\n")
    assert not any("end-of-life" in f.title for f in findings)
    assert any(f.severity == "info" for f in findings)


def test_tls_check_handles_unreachable(signed_scope, monkeypatch):
    import socket as sock_mod

    def boom(*a, **k):
        raise OSError("no route")

    monkeypatch.setattr(sock_mod, "create_connection", boom)
    assert checks.check_tls(signed_scope, "127.0.0.1", 443) == []
