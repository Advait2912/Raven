# Demo state manager and route controllers.
# Handles interactive step-by-step attack execution, policy checks, and evidence queries.

from typing import Any
from attack.idor import IDORAttack
from raven.ai.tutor import AITutor
from raven.core.policy import PolicyGate, Scope
from raven.core.store import EvidenceStore
from raven.target.lab import VulnerableLabTarget


class DemoController:
    """Manages state and sequential execution for the interactive demo."""

    def __init__(self) -> None:
        self.target = VulnerableLabTarget()
        self.attack = IDORAttack()
        self.evidence_store = EvidenceStore()
        self.policy_gate = PolicyGate(Scope())
        self.tutor = AITutor()
        self.current_step = 0
        self.last_result: Any = None
        self.session_token: str = ""

    def reset(self, preserve_patch: bool = False) -> dict[str, Any]:
        prev_patch = self.target.is_vulnerable
        self.target.reset_state()
        if preserve_patch:
            self.target.is_vulnerable = prev_patch
        self.evidence_store.clear()
        self.policy_gate = PolicyGate(Scope())
        self.current_step = 0
        self.last_result = None
        self.session_token = ""
        return {"status": "RESET_COMPLETED", "vulnerable": self.target.is_vulnerable}

    def toggle_patch(self, is_vulnerable: bool) -> dict[str, Any]:
        self.target.is_vulnerable = is_vulnerable
        return {"status": "UPDATED", "is_vulnerable": self.target.is_vulnerable}

    def run_full(self) -> dict[str, Any]:
        self.reset(preserve_patch=True)
        # Evaluate policy first
        pol = self.policy_gate.evaluate(
            action_id="idor_test",
            target_path="/api/orders/102",
            target_domain="localhost",
            prerequisites=["authenticated_session"],
            satisfied_prerequisites=["authenticated_session"],
        )
        if not pol.allowed:
            return {"status": "POLICY_REJECTED", "reason": pol.reason}

        result = self.attack.execute(self.target, self.evidence_store)
        self.last_result = result
        self.current_step = 3
        return {
            "policy": {"allowed": pol.allowed, "reason": pol.reason},
            "result": result.to_dict(),
            "target": {"name": self.target.name, "is_vulnerable": self.target.is_vulnerable},
        }

    def run_step(self, step_number: int) -> dict[str, Any]:
        """Execute a single phase of the attack for guided learning."""
        if step_number == 1:
            # Step 1: Authentication
            self.reset(preserve_patch=True)
            from raven.target.base import TargetRequest
            resp = self.target.handle_request(TargetRequest(
                method="POST",
                path="/api/auth/login",
                body={"username": "alice", "password": "alicepassword123"},
            ))
            data = resp.get_json() or {}
            self.session_token = data.get("token", "")
            self.current_step = 1
            return {
                "step": 1,
                "step_name": "AUTHENTICATION",
                "request": {"method": "POST", "path": "/api/auth/login", "body": {"username": "alice"}},
                "response": {"status": resp.status_code, "body": data},
                "actor": "usr_alice",
            }

        elif step_number == 2:
            # Step 2: Baseline Probe (Self-owned order 101)
            from raven.core.models import Evidence
            from raven.target.base import TargetRequest
            headers = {"Authorization": f"Bearer {self.session_token}"}
            resp = self.target.handle_request(TargetRequest(method="GET", path="/api/orders/101", headers=headers))
            data = resp.get_json() or {}
            e1 = Evidence(
                id=self.evidence_store.next_id(),
                evidence_type="HTTP_BASELINE_ACCESS",
                request_method="GET",
                request_path="/api/orders/101",
                request_headers=headers,
                request_body=None,
                response_status=resp.status_code,
                response_body=data,
                authenticated_actor="usr_alice",
                resource_owner=data.get("owner_id"),
                observation="Legitimate baseline access to own order 101.",
            )
            self.evidence_store.add_evidence(e1)
            self.current_step = 2
            return {
                "step": 2,
                "step_name": "BASELINE_PROBE",
                "evidence": e1.to_dict(),
                "request": {"method": "GET", "path": "/api/orders/101", "headers": headers},
                "response": {"status": resp.status_code, "body": data},
            }

        elif step_number == 3:
            # Step 3: Parameter Tampering & Validation
            from raven.core.models import Evidence
            from raven.core.validator import FindingValidator
            from raven.target.base import TargetRequest
            headers = {"Authorization": f"Bearer {self.session_token}"}
            resp = self.target.handle_request(TargetRequest(method="GET", path="/api/orders/102", headers=headers))
            data = resp.get_json() or {}
            owner = data.get("owner_id") if resp.status_code == 200 else None
            e2 = Evidence(
                id=self.evidence_store.next_id(),
                evidence_type="HTTP_TAMPER_ACCESS",
                request_method="GET",
                request_path="/api/orders/102",
                request_headers=headers,
                request_body=None,
                response_status=resp.status_code,
                response_body=data,
                authenticated_actor="usr_alice",
                resource_owner=owner,
                observation=f"Tampered access to order 102. Status: {resp.status_code}",
            )
            self.evidence_store.add_evidence(e2)

            all_ev = self.evidence_store.get_all_evidence()
            finding = FindingValidator.validate_idor(all_ev)
            if finding:
                self.evidence_store.add_finding(finding)

            self.current_step = 3
            return {
                "step": 3,
                "step_name": "PARAMETER_TAMPERING",
                "evidence": e2.to_dict(),
                "finding": finding.to_dict() if finding else None,
                "request": {"method": "GET", "path": "/api/orders/102", "headers": headers},
                "response": {"status": resp.status_code, "body": data},
                "confirmed": finding is not None,
            }

        return {"error": f"Unknown step {step_number}"}
