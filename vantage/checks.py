"""checks.py — safe, non-intrusive vulnerability checks.

Everything here *observes*; nothing attacks. The checks are:

* risky open ports (flagged by port/service, never probed for weakness),
* HTTP security header analysis,
* TLS certificate basics (expiry, self-signed, hostname match),
* service banner identification (with heuristic EOL-version notes).

Explicitly out of scope for Vantage: exploitation, brute forcing,
default-credential testing, fuzzing, and DoS. Each check asserts the
target is in the signed scope before any network I/O.
"""

from __future__ import annotations

import http.client
import re
import socket
import ssl
from datetime import datetime, timezone

from .findings import (
    CONFIRMED,
    HEURISTIC,
    HIGH,
    INFO,
    LOW,
    MEDIUM,
    Finding,
)
from .scope import Scope, assert_in_scope

# port -> (service, severity, why it is worth a look)
RISKY_PORTS: dict[int, tuple[str, str, str]] = {
    21: ("ftp", MEDIUM, "FTP transmits credentials in cleartext."),
    23: ("telnet", HIGH, "Telnet transmits everything, including credentials, in cleartext."),
    111: ("rpcbind", MEDIUM, "RPC portmapper exposed; historically abused for amplification and recon."),
    445: ("smb", MEDIUM, "SMB exposed to the network; a common lateral-movement target."),
    1433: ("mssql", MEDIUM, "Database listener reachable from the network."),
    1521: ("oracle-db", MEDIUM, "Database listener reachable from the network."),
    2049: ("nfs", MEDIUM, "NFS shares exposed; check export restrictions."),
    3306: ("mysql", MEDIUM, "Database listener reachable from the network."),
    3389: ("rdp", MEDIUM, "Remote desktop exposed; ensure MFA and lockout policy."),
    5432: ("postgres", MEDIUM, "Database listener reachable from the network."),
    5900: ("vnc", HIGH, "VNC exposed; often weakly authenticated and unencrypted."),
    6379: ("redis", HIGH, "Redis exposed; historically targeted with no auth by default."),
    9200: ("elasticsearch", HIGH, "Elasticsearch HTTP API exposed; often unauthenticated."),
    11211: ("memcached", HIGH, "Memcached exposed; abused for amplification when unauthenticated."),
    27017: ("mongodb", HIGH, "MongoDB exposed; check that authentication is enabled."),
}

SECURITY_HEADERS = {
    "strict-transport-security": (
        MEDIUM,
        "Strict-Transport-Security is not set; the site is open to protocol-downgrade attacks.",
    ),
    "content-security-policy": (
        LOW,
        "Content-Security-Policy is not set; XSS impact is harder to contain.",
    ),
    "x-frame-options": (
        LOW,
        "X-Frame-Options is not set; the site may be embeddable for clickjacking.",
    ),
    "x-content-type-options": (
        LOW,
        "X-Content-Type-Options is not set; browsers may MIME-sniff responses.",
    ),
    "referrer-policy": (
        INFO,
        "Referrer-Policy is not set; referrer leakage is uncontrolled.",
    ),
}

# (regex on banner) -> (service name, version group or None)
BANNER_PATTERNS: list[tuple[str, str, str | None]] = [
    (r"OpenSSH[_\s]([\d.]+p?\d*)", "OpenSSH", "1"),
    (r"SSH-2\.0-([\w.\-]+)", "SSH", "1"),
    (r"Apache/([\d.]+)", "Apache httpd", "1"),
    (r"nginx/([\d.]+)", "nginx", "1"),
    (r"Microsoft-IIS/([\d.]+)", "IIS", "1"),
    (r"vsFTPd ([\d.]+)", "vsFTPd", "1"),
    (r"Postfix", "Postfix SMTP", None),
    (r"Exim ([\d.]+)", "Exim", "1"),
    (r"Redis server v=([\d.]+)", "Redis", "1"),
    (r"MySQL", "MySQL", None),
]

# service -> versions at/below which the release is end-of-life (heuristic)
EOL_VERSIONS: dict[str, str] = {
    "OpenSSH": "7.9",
    "Apache httpd": "2.4.49",
    "nginx": "1.20.0",
}


def check_risky_ports(scope: Scope, host: str, open_ports: list[int]) -> list[Finding]:
    """Flag risky services purely by port number. No probing involved."""
    assert_in_scope(scope, host)
    findings: list[Finding] = []
    for port in open_ports:
        if port in RISKY_PORTS:
            service, severity, note = RISKY_PORTS[port]
            findings.append(
                Finding(
                    target=host,
                    port=port,
                    service=service,
                    title=f"Potentially risky service exposed: {service} on port {port}",
                    description=f"Port {port} ({service}) is open. {note} "
                    "This is a configuration observation, not a confirmed vulnerability.",
                    severity=severity,
                    confidence=HEURISTIC,
                    evidence=f"TCP connect to {host}:{port} succeeded.",
                    recommendation=f"Verify {service} on port {port} needs to be "
                    "network-reachable; restrict with firewall rules if not.",
                )
            )
    return findings


def _fetch_headers(host: str, port: int, use_tls: bool, timeout: float) -> dict[str, str]:
    if use_tls:
        conn = http.client.HTTPSConnection(host, port, timeout=timeout)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("HEAD", "/", headers={"Host": host, "User-Agent": "Vantage/0.1"})
        resp = conn.getresponse()
        resp.read()
        return {k.lower(): v for k, v in resp.getheaders()}
    finally:
        conn.close()


def check_http_headers(
    scope: Scope, host: str, port: int, use_tls: bool = False, timeout: float = 5.0
) -> list[Finding]:
    """Check for missing HTTP security headers. Read-only HEAD request."""
    assert_in_scope(scope, host, port)
    try:
        headers = _fetch_headers(host, port, use_tls, timeout)
    except (OSError, http.client.HTTPException):
        return []
    findings: list[Finding] = []
    scheme = "https" if use_tls else "http"
    for header, (severity, note) in SECURITY_HEADERS.items():
        if header == "strict-transport-security" and not use_tls:
            continue  # HSTS is only meaningful over TLS
        if header not in headers:
            findings.append(
                Finding(
                    target=host,
                    port=port,
                    service=f"{scheme}",
                    title=f"Missing security header: {header}",
                    description=note,
                    severity=severity,
                    confidence=CONFIRMED,
                    evidence=f"HEAD {scheme}://{host}:{port}/ returned no {header} header.",
                    recommendation=f"Set the {header} header on responses.",
                )
            )
    server = headers.get("server", "")
    if server:
        findings.append(
            Finding(
                target=host,
                port=port,
                service="http",
                title=f"Server header discloses software: {server}",
                description="The Server header reveals software and possibly version, "
                "aiding targeted attacks. Low risk on its own.",
                severity=INFO,
                confidence=CONFIRMED,
                evidence=f"Server: {server}",
                recommendation="Consider minimizing the Server header value.",
            )
        )
    return findings


def check_tls(scope: Scope, host: str, port: int = 443, timeout: float = 5.0) -> list[Finding]:
    """TLS certificate basics: expiry, self-signed, hostname match. Handshake only."""
    assert_in_scope(scope, host, port)
    findings: list[Finding] = []
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
    except (OSError, ssl.SSLError):
        return []
    if not cert:
        return []

    # Expiry
    try:
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        days_left = (not_after - datetime.now(timezone.utc)).days
        if days_left < 0:
            findings.append(_tls_finding(host, port, HIGH, "TLS certificate has expired",
                f"The certificate expired on {cert['notAfter']}.", CONFIRMED,
                f"notAfter={cert['notAfter']}", "Renew the certificate immediately."))
        elif days_left < 30:
            findings.append(_tls_finding(host, port, MEDIUM, "TLS certificate expiring soon",
                f"The certificate expires in {days_left} days ({cert['notAfter']}).", CONFIRMED,
                f"notAfter={cert['notAfter']}", "Renew the certificate before it lapses."))
    except (KeyError, ValueError):
        pass

    # Self-signed: issuer == subject
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    subject = dict(x[0] for x in cert.get("subject", ()))
    if issuer and issuer == subject:
        findings.append(_tls_finding(host, port, MEDIUM, "Self-signed TLS certificate",
            "The certificate is self-signed; clients cannot validate the server's identity.",
            CONFIRMED, f"issuer==subject ({issuer.get('commonName', '?')})",
            "Use a certificate from a trusted CA for public services."))

    # Hostname match (SANs then CN)
    sans = [v for t, v in cert.get("subjectAltName", ()) if t == "DNS"]
    cn = subject.get("commonName", "")
    if not _hostname_matches(host, sans, cn):
        findings.append(_tls_finding(host, port, MEDIUM, "TLS hostname mismatch",
            f"The certificate does not list {host} (SANs: {sans or 'none'}, CN: {cn or 'none'}).",
            CONFIRMED, f"SAN={sans} CN={cn}",
            "Issue a certificate covering this hostname."))
    return findings


def _tls_finding(host, port, severity, title, description, confidence, evidence, recommendation):
    return Finding(target=host, port=port, service="tls", title=title,
                   description=description, severity=severity, confidence=confidence,
                   evidence=evidence, recommendation=recommendation)


def _hostname_matches(host: str, sans: list[str], cn: str) -> bool:
    host = host.lower()
    for pattern in sans + ([cn] if cn else []):
        pattern = pattern.lower()
        if pattern == host:
            return True
        if pattern.startswith("*.") and host.endswith(pattern[1:]) and "." in host[: -len(pattern) + 1]:
            return True
    return False


def identify_service(banner: str) -> tuple[str, str | None]:
    """Match a banner against known software patterns. Returns (service, version)."""
    for pattern, service, group in BANNER_PATTERNS:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            version = match.group(int(group)) if group else None
            return service, version
    return ("unknown", None)


def check_banner(
    scope: Scope, host: str, port: int, banner: str
) -> list[Finding]:
    """Turn a grabbed banner into informational (and heuristic EOL) findings."""
    assert_in_scope(scope, host, port)
    if not banner.strip():
        return []
    service, version = identify_service(banner)
    findings = [
        Finding(
            target=host, port=port, service=service,
            title=f"Service identified: {service}" + (f" {version}" if version else ""),
            description="Banner grab identified the listening service. Informational.",
            severity=INFO, confidence=CONFIRMED,
            evidence=f"Banner: {banner[:200]}",
            recommendation="No action; used for scoping further review.",
        )
    ]
    if service in EOL_VERSIONS and version:
        cutoff = EOL_VERSIONS[service]
        if _version_lte(version, cutoff):
            findings.append(
                Finding(
                    target=host, port=port, service=service,
                    title=f"Possibly end-of-life software: {service} {version}",
                    description=f"Banner reports {service} {version}, at or below the "
                    f"heuristic end-of-life marker ({cutoff}). Version detection from "
                    "banners is heuristic — verify against the actual deployment.",
                    severity=MEDIUM, confidence=HEURISTIC,
                    evidence=f"Banner: {banner[:200]}",
                    recommendation=f"Confirm the {service} version and upgrade if it is "
                    "no longer receiving security updates.",
                )
            )
    return findings


def _version_lte(version: str, cutoff: str) -> bool:
    def parts(v: str) -> list[int]:
        return [int(p) for p in re.findall(r"\d+", v)][:4]
    return parts(version) <= parts(cutoff)
