# Tests for RedactionPipeline, HMAC EvidenceChain, and SQLite persistence.

import pytest
from raven.core.chain import EvidenceChain
from raven.core.db import Database
from raven.core.models import Evidence, Finding, FindingStatus, ScopeViolation
from raven.core.redaction import RedactionError, RedactionPipeline
from raven.core.store import EvidenceStore


def test_redaction_removes_sensitive_headers_and_tokens():
    raw_headers = {
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.do_not_leak",
        "Proxy-Authorization": "Basic YWxpY2U6cGFzc3dvcmQxMjM=",
        "Cookie": "session=secret123; user_pref=dark; auth_token=token456",
        "X-Api-Key": "raven_live_abcdef123456",
        "Content-Type": "application/json",
    }
    redacted = RedactionPipeline.redact_headers(raw_headers)

    assert "Bearer" in redacted["Authorization"]
    assert "do_not_leak" not in redacted["Authorization"]
    assert "YWxpY2U6" not in redacted["Proxy-Authorization"]
    assert "secret123" not in redacted["Cookie"]
    assert "token456" not in redacted["Cookie"]
    assert "user_pref=dark" in redacted["Cookie"]
    assert "abcdef123456" not in redacted["X-Api-Key"]
    assert redacted["Content-Type"] == "application/json"


def test_redaction_scrubs_nested_json_bodies():
    raw_body = {
        "user": {
            "username": "alice",
            "password": "SuperSecretPassword123!",
            "api_key": "sk-1234567890abcdef",
        },
        "orders": [
            {"id": 101, "item": "Laptop", "price": 999},
            {"id": 102, "access_token": "token_abc_xyz"},
        ],
        "notes": "Contact admin at db_password=dbsecretpw123",
    }
    redacted = RedactionPipeline.redact_value(raw_body)

    assert redacted["user"]["username"] == "alice"
    assert "SuperSecretPassword123!" not in redacted["user"]["password"]
    assert "[REDACTED:PASSWORD" in redacted["user"]["password"]
    assert "sk-1234567890abcdef" not in redacted["user"]["api_key"]
    assert redacted["orders"][0]["item"] == "Laptop"
    assert "token_abc_xyz" not in redacted["orders"][1]["access_token"]
    assert "dbsecretpw123" not in redacted["notes"]


def test_redaction_pipeline_evidence_fail_closed(monkeypatch):
    ev = Evidence(
        id="E01",
        evidence_type="HTTP_TEST",
        request_method="POST",
        request_path="/api/login",
        request_headers={"Authorization": "Bearer secret"},
        request_body={"password": "raw"},
        response_status=200,
        response_body={"token": "raw_jwt"},
        authenticated_actor="alice",
        resource_owner="alice",
        observation="Test login",
    )

    # Normal redaction works
    redacted = RedactionPipeline.redact_evidence(ev)
    assert "secret" not in redacted.request_headers["Authorization"]

    # When redaction is forced to raise an unexpected error, fail-closed guarantee halts write
    def broken_redact(data):
        raise RuntimeError("Unexpected pipeline failure")

    monkeypatch.setattr(RedactionPipeline, "redact_value", broken_redact)
    with pytest.raises(RedactionError):
        RedactionPipeline.redact_evidence(ev)


def test_evidence_chain_signing_and_tamper_detection():
    key = b"0" * 32
    chain = EvidenceChain(session_key=key)

    ev1 = Evidence(
        id="E01",
        evidence_type="HTTP_GET",
        request_method="GET",
        request_path="/api/orders/1",
        request_headers={"User-Agent": "RAVEN"},
        request_body=None,
        response_status=200,
        response_body={"order": 1, "owner": "alice"},
        authenticated_actor="alice",
        resource_owner="alice",
        observation="Alice accesses her order",
    )

    ev2 = Evidence(
        id="E02",
        evidence_type="HTTP_GET",
        request_method="GET",
        request_path="/api/orders/2",
        request_headers={"User-Agent": "RAVEN"},
        request_body=None,
        response_status=200,
        response_body={"order": 2, "owner": "bob"},
        authenticated_actor="alice",
        resource_owner="bob",
        observation="Alice accesses Bob's order (IDOR)",
    )

    chain.sign_evidence(ev1)
    chain.sign_evidence(ev2)

    assert ev1.chain_hash is not None
    assert ev2.chain_hash is not None
    assert ev1.chain_hash != ev2.chain_hash

    # Valid chain check
    valid, err = EvidenceChain.verify_chain([ev1, ev2], session_key=key)
    assert valid is True
    assert err is None

    # Tampering test: modify response_status in ev1
    ev1_tampered = Evidence(
        id="E01",
        evidence_type="HTTP_GET",
        request_method="GET",
        request_path="/api/orders/1",
        request_headers={"User-Agent": "RAVEN"},
        request_body=None,
        response_status=403,  # Tampered from 200 to 403
        response_body={"order": 1, "owner": "alice"},
        authenticated_actor="alice",
        resource_owner="alice",
        observation="Alice accesses her order",
        chain_hash=ev1.chain_hash,
        recorded_at=ev1.recorded_at,
    )

    tampered_valid, err = EvidenceChain.verify_chain([ev1_tampered, ev2], session_key=key)
    assert tampered_valid is False
    assert "Integrity check failed" in err

    # Deletion test: remove ev1
    deletion_valid, err = EvidenceChain.verify_chain([ev2], session_key=key)
    assert deletion_valid is False
    assert "Integrity check failed" in err

    # Reordering test: swap ev1 and ev2
    reordered_valid, err = EvidenceChain.verify_chain([ev2, ev1], session_key=key)
    assert reordered_valid is False


def test_evidence_store_integrated_redaction_and_chain(tmp_path):
    db_file = str(tmp_path / "test_raven.db")
    store = EvidenceStore(db_path=db_file)

    ev = Evidence(
        id=store.next_id(),
        evidence_type="HTTP_TEST",
        request_method="POST",
        request_path="/api/auth/login",
        request_headers={"Authorization": "Bearer my_super_secret_token"},
        request_body={"username": "alice", "password": "AliceSecretPassword!"},
        response_status=200,
        response_body={"token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"},
        authenticated_actor="alice",
        resource_owner="alice",
        observation="Logged in with password=AliceSecretPassword!",
    )

    stored = store.add_evidence(ev)

    # 1. Scrubbed in memory
    assert "my_super_secret_token" not in stored.request_headers["Authorization"]
    assert "AliceSecretPassword!" not in stored.request_body["password"]
    assert stored.chain_hash is not None

    # 2. Cryptographic integrity check passes
    valid, err = store.verify_integrity()
    assert valid is True
    assert err is None

    # 3. Persisted in SQLite without raw secrets
    db = Database(db_file)
    persisted = db.get_evidence()
    assert len(persisted) == 1
    assert "AliceSecretPassword!" not in persisted[0].request_body["password"]
    assert persisted[0].chain_hash == stored.chain_hash


def test_finding_status_lifecycle():
    f = Finding(
        id="FINDING-01",
        vulnerability_type="IDOR",
        severity="HIGH",
        endpoint="/api/orders/1",
        evidence_ids=["E01"],
        status=FindingStatus.CONFIRMED,
        confidence=0.95,
        cwe_id="CWE-639",
        cvss_score=8.5,
    )
    assert f.confirmed is True
    assert f.status == FindingStatus.CONFIRMED

    # State transition to INVALIDATED
    f.status = FindingStatus.INVALIDATED
    f.__post_init__()
    assert f.confirmed is False
