# Security boundary and guardrail tests for RAVEN.
# Verifies PolicyGate scope enforcement, request budgeting, path traversal defense,
# FindingValidator false-positive prevention, and target auth/method boundaries.

import pytest
from raven.core.models import Evidence
from raven.core.policy import PolicyGate, Scope
from raven.core.store import EvidenceStore
from raven.core.validator import FindingValidator
from raven.server.routes import DemoController
from raven.target.base import TargetRequest
from raven.target.lab import VulnerableLabTarget


@pytest.mark.parametrize(
    "domain",
    [
        "",
        "evil.com",
        "localhost.evil.com",
        "169.254.169.254",
        "10.0.0.1",
        "127.0.0.1:8080",
    ],
)
def test_policy_rejects_out_of_scope_domains(domain: str) -> None:
    gate = PolicyGate(Scope())
    decision = gate.evaluate(
        action_id="idor_test",
        target_path="/api/orders/102",
        target_domain=domain,
        prerequisites=[],
        satisfied_prerequisites=[],
    )
    assert decision.allowed is False
    assert "out of authorized scope" in decision.reason


@pytest.mark.parametrize(
    "path",
    [
        "/admin",
        "/api/users/1",
        "/api/orders/../admin",
        "/api/orders/../../etc/passwd",
        "/api/auth/login_bypass",
        "api/orders/101",
        r"/api/orders\..\admin",
        "/api/orders/101\x00.txt",
    ],
)
def test_policy_rejects_disallowed_and_traversal_paths(path: str) -> None:
    gate = PolicyGate(Scope())
    decision = gate.evaluate(
        action_id="idor_test",
        target_path=path,
        target_domain="localhost",
        prerequisites=[],
        satisfied_prerequisites=[],
    )
    assert decision.allowed is False
    assert "outside declared permitted paths" in decision.reason


def test_policy_enforces_request_budget_and_ignores_rejected_calls() -> None:
    gate = PolicyGate(Scope(max_requests=2))

    # Rejected calls should not consume request budget
    rejected = gate.evaluate("idor_test", "/admin", "localhost", [], [])
    assert rejected.allowed is False
    assert gate.scope.current_requests == 0

    assert gate.evaluate("idor_test", "/api/orders/101", "localhost", [], []).allowed is True
    assert gate.evaluate("idor_test", "/api/orders/102", "localhost", [], []).allowed is True

    over_budget = gate.evaluate("idor_test", "/api/orders/103", "localhost", [], [])
    assert over_budget.allowed is False
    assert "budget exceeded" in over_budget.reason


def test_validator_prevents_false_positives() -> None:
    def make_ev(ev_id: str, status: int, actor: str | None, owner: str | None) -> Evidence:
        return Evidence(
            id=ev_id,
            evidence_type="HTTP_TEST",
            request_method="GET",
            request_path="/api/orders/102",
            request_headers={},
            request_body=None,
            response_status=status,
            response_body={},
            authenticated_actor=actor,
            resource_owner=owner,
            observation="test",
        )

    # Non-200 responses must never confirm IDOR
    assert FindingValidator.validate_idor([make_ev("E01", 403, "usr_alice", "usr_bob")]) is None
    assert FindingValidator.validate_idor([make_ev("E02", 401, "usr_alice", "usr_bob")]) is None
    assert FindingValidator.validate_idor([make_ev("E03", 404, "usr_alice", "usr_bob")]) is None

    # Same-user access (owner == actor) is legitimate, not IDOR
    assert FindingValidator.validate_idor([make_ev("E04", 200, "usr_alice", "usr_alice")]) is None

    # Missing actor or owner metadata must not confirm IDOR
    assert FindingValidator.validate_idor([make_ev("E05", 200, None, "usr_bob")]) is None
    assert FindingValidator.validate_idor([make_ev("E06", 200, "usr_alice", None)]) is None


def test_target_blocks_unauthenticated_and_unsupported_methods() -> None:
    target = VulnerableLabTarget()

    # Missing or invalid Bearer token -> 401
    no_auth = target.handle_request(TargetRequest(method="GET", path="/api/orders/101"))
    assert no_auth.status_code == 401

    bad_auth = target.handle_request(
        TargetRequest(method="GET", path="/api/orders/101", headers={"Authorization": "Bearer invalid_tok"})
    )
    assert bad_auth.status_code == 401

    # Unsupported HTTP methods must not succeed
    token = target.db.users["usr_alice"].token
    for method in ("DELETE", "PUT", "PATCH"):
        resp = target.handle_request(
            TargetRequest(
                method=method,
                path="/api/orders/101",
                headers={"Authorization": f"Bearer {token}"},
            )
        )
        assert resp.status_code == 404

    # Invalid JSON body on login -> 400
    bad_login = target.handle_request(TargetRequest(method="POST", path="/api/auth/login", body="not-a-dict"))
    assert bad_login.status_code == 400


def test_evidence_store_isolation_and_controller_fail_closed() -> None:
    store = EvidenceStore()
    assert store.next_id() == "E01"
    assert store.next_id() == "E02"
    store.clear()
    assert store.next_id() == "E01"
    assert store.get_all_evidence() == []
    assert store.get_all_findings() == []

    # Controller refuses execution when PolicyGate scope excludes target
    controller = DemoController()
    controller.policy_gate = PolicyGate(Scope(allowed_domains=["other.local"]))
    res = controller.run_full()
    assert res["status"] == "POLICY_REJECTED"
    assert "out of authorized scope" in res["reason"]
