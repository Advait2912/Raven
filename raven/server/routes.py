# Demo state manager and route controllers.
# Handles multi-module assessments, interactive step-by-step attack execution,
# policy checks, evidence queries, and report generation for V1.

import json
from datetime import datetime, timezone
from typing import Any, Optional
from attack.cors import CORSMisconfigurationModule
from attack.disclosure import InformationDisclosureModule
from attack.exposure import ExcessiveDataExposureModule
from attack.fingerprint import TechnologyFingerprintModule
from attack.headers import SecurityHeadersModule
from attack.idor import IDORAttack
from raven.ai.tutor import AITutor
from raven.core.policy import PolicyGate, Scope
from raven.core.store import EvidenceStore
from raven.target.lab import VulnerableLabTarget


class DemoController:
    """Manages state and sequential execution for the interactive demo & V1 dashboard."""

    def __init__(self) -> None:
        self.target = VulnerableLabTarget()
        self.attack = IDORAttack()
        self.evidence_store = EvidenceStore()
        self.policy_scope = Scope(
            allowed_domains=["localhost", "127.0.0.1", "lab.local"],
            allowed_paths=["/", "/api/", "/.env", "/.git/"],
            max_requests=100,
        )
        self.policy_gate = PolicyGate(self.policy_scope)
        self.tutor = AITutor()
        self.current_step = 0
        self.last_result: Any = None
        self.session_token: str = ""
        self.mode: str = "student"  # "student" or "professional"
        self.assessment_id: str = "ASM-DEMO-01"

    def reset(self, preserve_patch: bool = False) -> dict[str, Any]:
        prev_patch = self.target.is_vulnerable
        self.target.reset_state()
        if preserve_patch:
            self.target.is_vulnerable = prev_patch
        self.evidence_store.clear()
        if not preserve_patch:
            self.policy_gate.scope.current_requests = 0
        self.current_step = 0
        self.last_result = None
        self.session_token = ""
        return {"status": "RESET_COMPLETED", "vulnerable": self.target.is_vulnerable}

    def toggle_patch(self, is_vulnerable: bool) -> dict[str, Any]:
        self.target.is_vulnerable = is_vulnerable
        return {"status": "UPDATED", "is_vulnerable": self.target.is_vulnerable}

    def set_mode(self, mode: str) -> dict[str, Any]:
        if mode in ("student", "professional"):
            self.mode = mode
        return {"status": "UPDATED", "mode": self.mode}

    def run_full(self) -> dict[str, Any]:
        """Runs the interactive IDOR vertical slice (maintains 100% backwards compatibility)."""
        self.reset(preserve_patch=True)
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

    def run_module(self, module_name: str) -> dict[str, Any]:
        """Execute a specific module or all 6 modules on the lab target."""
        self.reset(preserve_patch=True)
        results = []

        modules_to_run = []
        if module_name == "all":
            modules_to_run = ["headers", "disclosure", "fingerprint", "cors", "exposure", "idor"]
        else:
            modules_to_run = [module_name]

        scope = self.policy_scope

        for mod in modules_to_run:
            if mod == "idor":
                res = self.attack.execute(self.target, self.evidence_store)
                results.append(res)
            elif mod == "headers":
                m = SecurityHeadersModule()
                res = m.execute(self.target, store=self.evidence_store, scope=scope, endpoints=["/"])
                results.append(res)
            elif mod == "disclosure":
                m = InformationDisclosureModule()
                res = m.execute(self.target, store=self.evidence_store, scope=scope, custom_paths=["/.env", "/.git/HEAD"])
                results.append(res)
            elif mod == "fingerprint":
                m = TechnologyFingerprintModule()
                res = m.execute(self.target, store=self.evidence_store, scope=scope, endpoints=["/"])
                results.append(res)
            elif mod == "cors":
                m = CORSMisconfigurationModule()
                res = m.execute(self.target, store=self.evidence_store, scope=scope, target_path="/api/user/profile")
                results.append(res)
            elif mod == "exposure":
                m = ExcessiveDataExposureModule()
                res = m.execute(self.target, store=self.evidence_store, scope=scope, endpoints=["/api/user/profile"])
                results.append(res)

        all_findings = [f.to_dict() for f in self.evidence_store.get_all_findings()]
        all_evidence = [e.to_dict() for e in self.evidence_store.get_all_evidence()]
        integrity_ok, integrity_err = self.evidence_store.verify_integrity()

        return {
            "module_requested": module_name,
            "target": {"name": self.target.name, "is_vulnerable": self.target.is_vulnerable},
            "modules_run": [r.to_dict() for r in results],
            "total_findings": len(all_findings),
            "findings": all_findings,
            "total_evidence": len(all_evidence),
            "evidence": all_evidence,
            "integrity_verified": integrity_ok,
            "integrity_error": integrity_err,
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

    def generate_report(self, format_type: str = "json") -> Any:
        """Export audit report of current assessment in JSON or Markdown."""
        findings = [f.to_dict() for f in self.evidence_store.get_all_findings()]
        evidence = [e.to_dict() for e in self.evidence_store.get_all_evidence()]
        integrity_ok, integrity_err = self.evidence_store.verify_integrity()

        report_data = {
            "title": "RAVEN Security Assessment & Vulnerability Report",
            "assessment_id": self.assessment_id,
            "target": self.target.name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target_state": "Vulnerable" if self.target.is_vulnerable else "Remediated",
            "integrity_chain_valid": integrity_ok,
            "total_findings": len(findings),
            "findings": findings,
            "evidence_count": len(evidence),
            "evidence": evidence,
        }

        if format_type.lower() == "markdown":
            md = [
                f"# {report_data['title']}",
                f"**Assessment ID:** `{report_data['assessment_id']}`  ",
                f"**Target:** {report_data['target']}  ",
                f"**Timestamp:** {report_data['timestamp']}  ",
                f"**Target State:** {report_data['target_state']}  ",
                f"**HMAC Evidence Chain Integrity:** {'✓ VALID & UNBROKEN' if integrity_ok else '✗ INTEGRITY VIOLATION'}  ",
                "",
                "---",
                "",
                "## Summary of Findings",
                "",
            ]
            if not findings:
                md.append("No vulnerabilities confirmed. Target is secure or remediated.\n")
            else:
                for f in findings:
                    md.append(f"### [{f.get('severity', 'INFO')}] {f.get('vulnerability_type')}")
                    md.append(f"- **Endpoint:** `{f.get('endpoint')}`")
                    md.append(f"- **Status:** `{f.get('status')}`")
                    md.append(f"- **Evidence IDs:** {', '.join(f.get('evidence_ids', []))}")
                    md.append(f"- **Root Cause:** {f.get('root_cause', 'N/A')}")
                    md.append(f"- **Remediation:** `{f.get('remediation', 'N/A')}`\n")

            md.append("## Evidence Chain (Cryptographically Signed & Redacted)\n")
            for e in evidence:
                md.append(f"- **[{e['id']}]** `{e['request_method']} {e['request_path']}` $\\to$ HTTP {e['response_status']} | HMAC: `{e.get('chain_hash', '')[:16]}...`")

            return "\n".join(md)

        return report_data
