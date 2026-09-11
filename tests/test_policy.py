# Unit tests for deterministic policy gate.

import pytest
from raven.core.policy import PolicyGate, Scope


def test_policy_gate_allow() -> None:
    gate = PolicyGate(Scope())
    decision = gate.evaluate(
        action_id="idor_test",
        target_path="/api/orders/102",
        target_domain="localhost",
        prerequisites=["auth"],
        satisfied_prerequisites=["auth"],
    )
    assert decision.allowed is True


def test_policy_gate_scope_domain_rejection() -> None:
    gate = PolicyGate(Scope(allowed_domains=["localhost"]))
    decision = gate.evaluate(
        action_id="idor_test",
        target_path="/api/orders/102",
        target_domain="malicious-site.com",
        prerequisites=[],
        satisfied_prerequisites=[],
    )
    assert decision.allowed is False
    assert "out of authorized scope" in decision.reason


def test_policy_gate_prerequisite_rejection() -> None:
    gate = PolicyGate(Scope())
    decision = gate.evaluate(
        action_id="idor_test",
        target_path="/api/orders/102",
        target_domain="localhost",
        prerequisites=["authenticated_session", "admin_role"],
        satisfied_prerequisites=["authenticated_session"],
    )
    assert decision.allowed is False
    assert "admin_role" in decision.reason
