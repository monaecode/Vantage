"""Shared pytest fixtures."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vantage import scope as scope_mod
from vantage import store


SIGNED_SCOPE_YAML = """\
engagement: "test lab"
targets:
  - host: 127.0.0.1
    ports: [22, 80, 443, 8000, 8080]
  - host: 10.9.0.0/24
exclusions:
  - host: 10.9.0.99
    reason: "do not touch"
authorization:
  signed_by: "Test Operator"
  signed_date: "2026-10-10"
  statement: "Written authorization on file."
"""

UNSIGNED_SCOPE_YAML = """\
engagement: "test lab"
targets:
  - host: 127.0.0.1
authorization:
  signed_by: ""
  signed_date: ""
  statement: ""
"""


@pytest.fixture
def signed_scope():
    return scope_mod.load_scope_text(SIGNED_SCOPE_YAML)


@pytest.fixture
def unsigned_scope():
    return scope_mod.load_scope_text(UNSIGNED_SCOPE_YAML)


@pytest.fixture
def db_path(tmp_path):
    path = tmp_path / "test.db"
    store.init_db(path)
    return path


@pytest.fixture
def audit_path(tmp_path):
    return tmp_path / "audit.jsonl"
