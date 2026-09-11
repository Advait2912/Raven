# Unit tests for vulnerable lab target.

import pytest
from raven.target.base import TargetRequest
from raven.target.lab import VulnerableLabTarget


@pytest.fixture
def target() -> VulnerableLabTarget:
    return VulnerableLabTarget()


def test_target_health(target: VulnerableLabTarget) -> None:
    resp = target.handle_request(TargetRequest(method="GET", path="/api/health"))
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "online"


def test_target_auth_success(target: VulnerableLabTarget) -> None:
    resp = target.handle_request(TargetRequest(
        method="POST",
        path="/api/auth/login",
        body={"username": "alice", "password": "alicepassword123"},
    ))
    assert resp.status_code == 200
    assert "token" in resp.get_json()


def test_target_idor_vulnerability(target: VulnerableLabTarget) -> None:
    # Alice requests Bob's order 102
    token = target.db.users["usr_alice"].token
    resp = target.handle_request(TargetRequest(
        method="GET",
        path="/api/orders/102",
        headers={"Authorization": f"Bearer {token}"},
    ))
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["order_id"] == "102"
    assert data["owner_id"] == "usr_bob"  # Leaked!


def test_target_remediation_patch(target: VulnerableLabTarget) -> None:
    # When patched, Alice requesting Bob's order returns 403 Forbidden
    target.is_vulnerable = False
    token = target.db.users["usr_alice"].token
    resp = target.handle_request(TargetRequest(
        method="GET",
        path="/api/orders/102",
        headers={"Authorization": f"Bearer {token}"},
    ))
    assert resp.status_code == 403
    assert "Forbidden" in resp.get_json()["error"]
