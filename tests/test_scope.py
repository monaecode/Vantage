"""Tests for the authorization gate and scope enforcement."""

import pytest

from vantage.scope import (
    ScopeNotAuthorized,
    ScopeViolation,
    assert_in_scope,
    is_signed,
    iter_targets,
    load_scope_text,
    require_authorization,
    scope_allows,
)


def test_signed_scope_loads(signed_scope):
    assert signed_scope.engagement == "test lab"
    assert len(signed_scope.targets) == 2
    assert is_signed(signed_scope)


def test_unsigned_scope_detected(unsigned_scope):
    assert not is_signed(unsigned_scope)


def test_scope_requires_targets():
    with pytest.raises(ValueError, match="non-empty 'targets'"):
        load_scope_text("engagement: x\ntargets: []\n")


def test_two_key_rule(signed_scope, unsigned_scope):
    # Missing explicit confirmation -> refused
    with pytest.raises(ScopeNotAuthorized):
        require_authorization(signed_scope, confirmed=False)
    # Unsigned scope even with confirmation -> refused
    with pytest.raises(ScopeNotAuthorized):
        require_authorization(unsigned_scope, confirmed=True)
    # Both keys -> passes silently
    require_authorization(signed_scope, confirmed=True)


def test_in_scope_host(signed_scope):
    assert scope_allows(signed_scope, "127.0.0.1")
    assert_in_scope(signed_scope, "127.0.0.1")


def test_out_of_scope_host_refused(signed_scope):
    assert not scope_allows(signed_scope, "8.8.8.8")
    with pytest.raises(ScopeViolation):
        assert_in_scope(signed_scope, "8.8.8.8")


def test_cidr_target_matches(signed_scope):
    assert scope_allows(signed_scope, "10.9.0.23")
    assert not scope_allows(signed_scope, "10.9.1.23")


def test_exclusion_wins_over_cidr(signed_scope):
    # 10.9.0.99 is inside 10.9.0.0/24 but explicitly excluded
    assert not scope_allows(signed_scope, "10.9.0.99")
    with pytest.raises(ScopeViolation, match="EXCLUD"):
        assert_in_scope(signed_scope, "10.9.0.99")


def test_port_restriction(signed_scope):
    assert_in_scope(signed_scope, "127.0.0.1", 80)
    with pytest.raises(ScopeViolation, match="Port 25"):
        assert_in_scope(signed_scope, "127.0.0.1", 25)


def test_localhost_aliases():
    scope = load_scope_text(
        "targets:\n  - host: localhost\nauthorization:\n"
        "  signed_by: x\n  signed_date: y\n  statement: z\n"
    )
    assert scope_allows(scope, "127.0.0.1")
    assert scope_allows(scope, "localhost")


def test_iter_targets(signed_scope):
    pairs = list(iter_targets(signed_scope))
    assert pairs[0] == ("127.0.0.1", [22, 80, 443, 8000, 8080])
    assert pairs[1] == ("10.9.0.0/24", None)
