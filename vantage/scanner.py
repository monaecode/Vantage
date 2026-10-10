"""scanner.py — TCP connect port scan in pure Python.

No root required, no nmap dependency: plain ``socket.connect_ex`` with a
short timeout, run across a thread pool. Every port probe asserts the
target is in the signed scope first; anything out of scope raises
:exc:`ScopeViolation` before a single packet is sent.
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from .scope import Scope, assert_in_scope

# A pragmatic default set: the ports most worth knowing about first.
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1433, 1521, 1723, 3306, 3389, 5432, 5900, 6379,
    8080, 8443, 8888, 9200, 27017,
]

HTTP_LIKE_PORTS = {80, 8080, 8888, 8000, 5000, 3000}
TLS_LIKE_PORTS = {443, 8443}


@dataclass
class PortResult:
    host: str
    port: int
    is_open: bool
    banner: str = ""
    service_hint: str = ""


def _grab_banner(sock: socket.socket, port: int, timeout: float) -> str:
    """Read a service banner. Passive first; one minimal HEAD for HTTP."""
    sock.settimeout(timeout)
    try:
        data = sock.recv(1024)
        if data:
            return data.decode("utf-8", errors="replace").strip()[:512]
    except (OSError, socket.timeout):
        pass
    if port in HTTP_LIKE_PORTS:
        try:
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: x\r\n\r\n")
            data = sock.recv(2048)
            return data.decode("utf-8", errors="replace").strip()[:512]
        except (OSError, socket.timeout):
            pass
    return ""


def scan_port(scope: Scope, host: str, port: int, timeout: float = 1.0) -> PortResult:
    """TCP-connect one port. Scope is checked before connecting."""
    assert_in_scope(scope, host, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if sock.connect_ex((host, port)) != 0:
            # connect_ex returns 0 on success; anything else is closed/filtered
            return PortResult(host=host, port=port, is_open=False)
        banner = _grab_banner(sock, port, timeout)
        return PortResult(host=host, port=port, is_open=True, banner=banner)
    finally:
        sock.close()


def scan_host(
    scope: Scope,
    host: str,
    ports: list[int] | None = None,
    timeout: float = 1.0,
    workers: int = 50,
) -> list[PortResult]:
    """Connect-scan ``ports`` on ``host``. Scope is checked per port."""
    assert_in_scope(scope, host)
    ports = ports if ports is not None else DEFAULT_PORTS
    results: list[PortResult] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(scan_port, scope, host, p, timeout) for p in ports]
        for future in futures:
            results.append(future.result())
    return sorted(results, key=lambda r: r.port)
