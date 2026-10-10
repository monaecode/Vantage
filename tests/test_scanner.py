"""Tests for the TCP connect scanner, with mocked sockets (no network)."""

import socket

import pytest

from vantage import scanner
from vantage.scope import ScopeViolation


class FakeSocket:
    """Stand-in for socket.socket. open_ports maps port -> banner bytes."""

    open_ports: dict[int, bytes] = {}

    def __init__(self, *args, **kwargs):
        self._port = None

    def connect_ex(self, address):
        host, port = address
        self._port = port
        if port in self.open_ports:
            return 0
        return 111  # ECONNREFUSED

    def recv(self, n):
        return self.open_ports.get(self._port, b"")

    def sendall(self, data):
        pass

    def settimeout(self, t):
        pass

    def close(self):
        pass


@pytest.fixture
def fake_socket(monkeypatch):
    FakeSocket.open_ports = {22: b"SSH-2.0-OpenSSH_8.9\r\n", 80: b""}
    monkeypatch.setattr(socket, "socket", FakeSocket)
    return FakeSocket


def test_open_port_detected(signed_scope, fake_socket):
    result = scanner.scan_port(signed_scope, "127.0.0.1", 22)
    assert result.is_open
    assert "OpenSSH" in result.banner


def test_closed_port(signed_scope, fake_socket):
    # 443 is in the fixture's allowed port list but not "open" in the fake
    result = scanner.scan_port(signed_scope, "127.0.0.1", 443)
    assert not result.is_open
    assert result.banner == ""


def test_out_of_scope_port_refused(signed_scope, fake_socket):
    # 127.0.0.1 is in scope but port 23 is not in its allowed list
    with pytest.raises(ScopeViolation):
        scanner.scan_port(signed_scope, "127.0.0.1", 23)


def test_out_of_scope_host_refused(signed_scope, fake_socket):
    with pytest.raises(ScopeViolation):
        scanner.scan_port(signed_scope, "8.8.8.8", 80)


def test_scan_host_sorts_and_covers(signed_scope, fake_socket, monkeypatch):
    # scan_host asserts scope for the host, then per port
    results = scanner.scan_host(signed_scope, "127.0.0.1", ports=[80, 22, 443])
    assert [r.port for r in results] == [22, 80, 443]
    assert [r.is_open for r in results] == [True, True, False]


def test_http_banner_probe(signed_scope, fake_socket, monkeypatch):
    seen = {}

    class HttpFake(FakeSocket):
        def recv(self, n):
            seen["probed"] = True
            if not seen.get("banner_sent"):
                seen["banner_sent"] = True
                return b""
            return b"HTTP/1.1 200 OK\r\nServer: nginx/1.20.0\r\n\r\n"

    FakeSocket.open_ports = {80: b""}
    monkeypatch.setattr(socket, "socket", HttpFake)
    result = scanner.scan_port(signed_scope, "127.0.0.1", 80)
    assert result.is_open
    assert "nginx" in result.banner
