"""Vantage — AI-assisted vulnerability assessment, running entirely on your machine.

Every scan runs behind an authorization gate: a signed scope file must name
the target and the operator must explicitly confirm authorization. Anything
outside the signed scope is refused before any network I/O happens.

Pipeline: scope gate -> recon -> TCP port scan -> safe checks ->
severity-ranked findings -> SQLite store + audit log.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
