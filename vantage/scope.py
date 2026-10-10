"""scope.py — signed engagement scope and the authorization gate.

Safety model (two keys, both required before any network I/O):
  1. The operator explicitly confirms authorization
     (``--i-am-authorized`` on the CLI, ``authorized: true`` on the API).
  2. A scope file lists the target and carries a completed authorization
     block (``signed_by``, ``signed_date``, ``statement``).

Every phase calls :func:`scope_allows` before touching a target. A target
outside the signed scope — or on the exclusions list — raises
:exc:`ScopeViolation` and the run stops immediately.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path

import yaml


class ScopeViolation(Exception):
    """Raised when a target is outside the authorized engagement scope."""


class ScopeNotAuthorized(Exception):
    """Raised when the scope file is unsigned or authorization is unconfirmed."""


LOCALHOST_ALIASES = {"localhost", "127.0.0.1", "::1"}


@dataclass
class ScopeTarget:
    host: str
    ports: list[int] | None = None  # None = any port allowed


@dataclass
class Scope:
    """A parsed, structurally valid engagement scope."""

    engagement: str = ""
    targets: list[ScopeTarget] = field(default_factory=list)
    exclusions: list[dict] = field(default_factory=list)
    authorization: dict = field(default_factory=dict)
    raw: dict = field(default_factory=dict)


def _parse_target(entry: dict) -> ScopeTarget:
    host = entry.get("host")
    if not host or not isinstance(host, str):
        raise ValueError(f"target entry needs a 'host' string: {entry!r}")
    ports = entry.get("ports")
    if ports is not None:
        ports = [int(p) for p in ports]
    return ScopeTarget(host=host.strip(), ports=ports)


def load_scope_text(text: str) -> Scope:
    """Parse and structurally validate scope YAML given as text."""
    data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        raise ValueError("scope file must be a YAML mapping")
    raw_targets = data.get("targets")
    if not isinstance(raw_targets, list) or not raw_targets:
        raise ValueError("scope file must define a non-empty 'targets' list")
    targets = [_parse_target(t) for t in raw_targets]
    exclusions = data.get("exclusions") or []
    if not isinstance(exclusions, list):
        raise ValueError("'exclusions' must be a list")
    return Scope(
        engagement=str(data.get("engagement") or ""),
        targets=targets,
        exclusions=exclusions,
        authorization=data.get("authorization") or {},
        raw=data,
    )


def load_scope_file(path: str | Path) -> Scope:
    """Load a scope file from disk and validate it."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"scope file not found: {path}")
    return load_scope_text(path.read_text(encoding="utf-8"))


def is_signed(scope: Scope) -> bool:
    """True only when the authorization block is fully completed."""
    auth = scope.authorization or {}
    return bool(auth.get("signed_by") and auth.get("signed_date") and auth.get("statement"))


def require_authorization(scope: Scope, confirmed: bool) -> None:
    """Enforce the two-key rule. Raises ScopeNotAuthorized on failure."""
    if not confirmed:
        raise ScopeNotAuthorized(
            "Refusing to scan: confirm you hold written authorization "
            "to test these targets (CLI: --i-am-authorized, API: authorized=true)."
        )
    if not is_signed(scope):
        raise ScopeNotAuthorized(
            "Refusing to scan: the scope file's authorization block is not "
            "signed (needs signed_by, signed_date, and statement)."
        )


def _host_matches(entry_host: str, host: str) -> bool:
    """Match a host against a scope entry: exact, localhost alias, or CIDR."""
    entry_host = entry_host.strip().lower()
    host = host.strip().lower()
    if entry_host in LOCALHOST_ALIASES and host in LOCALHOST_ALIASES:
        return True
    if entry_host == host:
        return True
    try:  # CIDR entry such as 10.0.0.0/24
        network = ipaddress.ip_network(entry_host, strict=False)
        return ipaddress.ip_address(host) in network
    except ValueError:
        return False


def scope_allows(scope: Scope, host: str, port: int | None = None) -> bool:
    """Return True if host (and port, when given) is covered by the scope."""
    for excl in scope.exclusions:
        if _host_matches(str(excl.get("host", "")), host):
            return False
    for target in scope.targets:
        if _host_matches(target.host, host):
            if port is None or not target.ports or port in target.ports:
                return True
    return False


def assert_in_scope(scope: Scope, host: str, port: int | None = None) -> None:
    """Raise ScopeViolation unless host (and port, if given) is authorized."""
    for excl in scope.exclusions:
        if _host_matches(str(excl.get("host", "")), host):
            raise ScopeViolation(
                f"Target {host} is explicitly EXCLUDED from scope "
                f"({excl.get('reason', 'no reason given')}). Refusing."
            )
    for target in scope.targets:
        if _host_matches(target.host, host):
            if port is None or not target.ports or port in target.ports:
                return
            raise ScopeViolation(
                f"Port {port} on {host} is outside the signed scope "
                f"(allowed ports: {target.ports}). Refusing."
            )
    raise ScopeViolation(
        f"Target {host} is NOT in the authorized engagement scope. Refusing."
    )


def iter_targets(scope: Scope):
    """Yield (host, ports|None) for every in-scope target."""
    for target in scope.targets:
        yield target.host, target.ports
