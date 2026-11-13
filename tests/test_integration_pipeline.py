# End-to-end integration test suite for RAVEN.
# Tests the full cycle: Live HTTP Server -> NetworkGateway (SSRF & Rebinding check) ->
# Evidence Collection -> RedactionPipeline -> HMAC EvidenceChain -> SQLite Persistence ->
# Tamper Detection -> Database Restart & Recovery.

import json
import sqlite3
import threading
from http.server import ThreadingHTTPServer
import pytest
from raven.core.chain import EvidenceChain
from raven.core.db import Database
from raven.core.models import Evidence, Finding, FindingStatus, ScopeViolation
from raven.core.network import NetworkGateway, NetworkGatewayError
from raven.core.policy import Scope
from raven.core.redaction import RedactionPipeline
from raven.core.store import EvidenceStore
from raven.core.validator import FindingValidator
from raven.server.app import RavenRequestHandler


@pytest.fixture(scope="module")
def live_server():
    """Start the real RAVEN server on an ephemeral loopback port for integration tests."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), RavenRequestHandler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()


def test_end_to_end_network_gateway_against_live_server(live_server):
    """NetworkGateway successfully connects to live RAVEN server, validates scope and methods."""
    scope = Scope(
        allowed_domains=["127.0.0.1", "localhost"],
        allowed_paths=["/api/health", "/api/demo/"],
        allowed_methods=["GET", "POST"],
        allow_loopback=True,
    )
    gw = NetworkGateway(scope=scope)

    # 1. Valid request to /api/health
    resp = gw.execute_request("GET", f"{live_server}/api/health")
    assert resp.status_code == 200
    assert resp.resolved_ip == "127.0.0.1"
    data = json.loads(resp.body)
    assert data["service"] == "raven"
    assert data["status"] == "online"

    # 2. Scope boundary rejection: path outside allowed_paths
    with pytest.raises(NetworkGatewayError, match="PolicyGate rejected"):
        gw.execute_request("GET", f"{live_server}/api/unauthorized_path")

    # 3. Method restriction rejection: DELETE is not in allowed_methods
    with pytest.raises(NetworkGatewayError, match="HTTP method 'DELETE' not allowed"):
        gw.execute_request("DELETE", f"{live_server}/api/health")


def test_end_to_end_evidence_collection_redaction_and_tamper_detection(tmp_path):
    """Full lifecycle: Evidence collection -> Redaction -> HMAC signing -> SQLite -> Tamper detection."""
    db_path = str(tmp_path / "raven_integration.db")
    assessment_id = "ASM-2026-TEST"
    store = EvidenceStore(db_path=db_path, assessment_id=assessment_id)

    # Step 1: Record simulated login evidence with raw credentials and JWT
    raw_ev1 = Evidence(
        id=store.next_id(),
        evidence_type="HTTP_AUTH_LOGIN",
        request_method="POST",
        request_path="/api/auth/login",
        request_headers={
            "User-Agent": "RAVEN/1.0",
            "Authorization": "Basic dXNyX2FsaWNlOmFsaWNlcGFzc3dvcmQxMjM=",
        },
        request_body={"username": "usr_alice", "password": "alicepassword123"},
        response_status=200,
        response_headers={"Content-Type": "application/json", "Set-Cookie": "session=secret_token_123; HttpOnly"},
        response_body={"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.sig", "user_id": "usr_alice"},
        authenticated_actor=None,
        resource_owner=None,
        observation="Authentication succeeded for usr_alice with password=alicepassword123",
        assessment_id=assessment_id,
    )

    stored_ev1 = store.add_evidence(raw_ev1)

    # Verify redaction before storage
    assert "alicepassword123" not in stored_ev1.request_body["password"]
    assert "dXNyX2FsaWNl" not in stored_ev1.request_headers["Authorization"]
    assert "secret_token_123" not in stored_ev1.response_headers["Set-Cookie"]
    assert "alicepassword123" not in stored_ev1.observation

    # Step 2: Record baseline self-owned resource access
    raw_ev2 = Evidence(
        id=store.next_id(),
        evidence_type="HTTP_BASELINE_ACCESS",
        request_method="GET",
        request_path="/api/orders/101",
        request_headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.sig"},
        request_body=None,
        response_status=200,
        response_body={"order_id": 101, "owner_id": "usr_alice", "total": 250},
        authenticated_actor="usr_alice",
        resource_owner="usr_alice",
        observation="usr_alice successfully retrieved own order 101",
        assessment_id=assessment_id,
    )
    stored_ev2 = store.add_evidence(raw_ev2)

    # Step 3: Record cross-user IDOR access (Alice accessing Bob's order)
    raw_ev3 = Evidence(
        id=store.next_id(),
        evidence_type="HTTP_TAMPER_ACCESS",
        request_method="GET",
        request_path="/api/orders/102",
        request_headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.sig"},
        request_body=None,
        response_status=200,
        response_body={"order_id": 102, "owner_id": "usr_bob", "total": 9999},
        authenticated_actor="usr_alice",
        resource_owner="usr_bob",
        observation="Cross-user resource leakage: usr_alice accessed order 102 belonging to usr_bob",
        assessment_id=assessment_id,
    )
    stored_ev3 = store.add_evidence(raw_ev3)

    # Step 4: Run deterministic FindingValidator
    finding = FindingValidator.validate_idor(store.get_all_evidence())
    assert finding is not None
    assert finding.confirmed is True
    assert "E03" in finding.evidence_ids
    store.add_finding(finding)

    # Step 5: Verify HMAC chain integrity across all 3 evidence items
    valid, err = store.verify_integrity()
    assert valid is True
    assert err is None

    # Step 6: Tamper detection via direct raw SQLite modification
    # Directly tamper with evidence in the database to simulate malicious tampering
    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE evidence SET response_status = 403 WHERE id = 'E03'")
    conn.commit()
    conn.close()

    # Reload evidence from the tampered database
    db = Database(db_path)
    tampered_evidence = db.get_evidence(assessment_id=assessment_id)
    assert len(tampered_evidence) == 3

    # Cryptographic verification MUST detect the tamper and fail
    is_valid, tamper_reason = EvidenceChain.verify_chain(
        evidence_list=tampered_evidence,
        session_key=store.session_key,
    )
    assert is_valid is False
    assert "Integrity check failed at evidence E03" in tamper_reason


def test_end_to_end_database_restart_and_state_recovery(tmp_path):
    """Database state persists and reloads cleanly across server restart cycles."""
    db_path = str(tmp_path / "persistence_test.db")
    assessment_id = "ASM-PERSIST-01"

    # Phase 1: First container session writes data
    session_store = EvidenceStore(db_path=db_path, assessment_id=assessment_id)
    session_key = session_store.session_key

    ev = Evidence(
        id=session_store.next_id(),
        evidence_type="HTTP_TEST",
        request_method="GET",
        request_path="/api/orders/1",
        request_headers={"Accept": "application/json"},
        request_body=None,
        response_status=200,
        response_body={"id": 1, "status": "active"},
        authenticated_actor="alice",
        resource_owner="alice",
        observation="Baseline request",
        assessment_id=assessment_id,
    )
    session_store.add_evidence(ev)

    finding = Finding(
        id="FINDING-P01",
        vulnerability_type="IDOR",
        severity="HIGH",
        endpoint="/api/orders/1",
        evidence_ids=["E01"],
        status=FindingStatus.CONFIRMED,
        confidence=1.0,
        assessment_id=assessment_id,
    )
    session_store.add_finding(finding)

    violation = ScopeViolation(
        id="VIO-01",
        violation_type="PRIVATE_IP",
        attempted_target="http://10.0.0.1/",
        blocked_by="NetworkGateway",
        details="RFC1918 blocked",
        assessment_id=assessment_id,
    )
    session_store.add_scope_violation(violation)

    # Phase 2: Simulate complete server termination (store object discarded)
    del session_store

    # Phase 3: Start new server instance connecting to the same SQLite volume
    restarted_db = Database(db_path)
    recovered_evidence = restarted_db.get_evidence(assessment_id=assessment_id)
    recovered_findings = restarted_db.get_findings(assessment_id=assessment_id)
    recovered_violations = restarted_db.get_scope_violations(assessment_id=assessment_id)

    assert len(recovered_evidence) == 1
    assert recovered_evidence[0].id == "E01"
    assert recovered_evidence[0].chain_hash is not None

    assert len(recovered_findings) == 1
    assert recovered_findings[0].id == "FINDING-P01"
    assert recovered_findings[0].status == FindingStatus.CONFIRMED

    assert len(recovered_violations) == 1
    assert recovered_violations[0].violation_type == "PRIVATE_IP"

    # Integrity verification on recovered data passes
    valid, err = EvidenceChain.verify_chain(recovered_evidence, session_key=session_key)
    assert valid is True
    assert err is None
