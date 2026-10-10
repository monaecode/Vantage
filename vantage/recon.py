"""recon.py — host discovery, strictly inside the signed scope.

Recon here is deliberately quiet: DNS forward/reverse resolution only.
No ping sweeps, no aggressive enumeration. Every function asserts the
target is in scope before any network I/O.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field

from .scope import Scope, assert_in_scope


@dataclass
class HostInfo:
    host: str
    addresses: list[str] = field(default_factory=list)
    reverse_names: list[str] = field(default_factory=list)


def resolve_host(scope: Scope, host: str) -> HostInfo:
    """Resolve a hostname to IP addresses. Scope is checked first."""
    assert_in_scope(scope, host)
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise RuntimeError(f"could not resolve {host}: {exc}") from exc
    addresses: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in addresses:
            addresses.append(ip)
    return HostInfo(host=host, addresses=addresses)


def reverse_lookup(scope: Scope, ip: str) -> str | None:
    """Reverse-DNS an IP address. Scope is checked first."""
    assert_in_scope(scope, ip)
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except (socket.herror, socket.gaierror, OSError):
        return None


def discover(scope: Scope) -> list[HostInfo]:
    """Resolve every in-scope target. Returns one HostInfo per target."""
    results: list[HostInfo] = []
    for host, _ports in scope.targets:
        # CIDR targets describe ranges, not single hosts: record the range
        # itself rather than sweeping it.
        if "/" in host:
            results.append(HostInfo(host=host, addresses=[]))
            continue
        info = resolve_host(scope, host)
        for ip in info.addresses:
            name = reverse_lookup(scope, ip)
            if name and name not in info.reverse_names:
                info.reverse_names.append(name)
        results.append(info)
    return results
