# CORS Misconfiguration Assessment Module.
# Formulated according to target definition, evidence store, PolicyGate, and deterministic validation.

import json
import urllib.parse
from typing import Any, Optional, Union
from raven.core.models import AttackResult, Evidence, Finding, FindingStatus, Observation
from raven.core.network import NetworkGateway, NetworkGatewayError
from raven.core.policy import Scope
from raven.core.store import EvidenceStore
from raven.core.validator import FindingValidator
from raven.target.base import BaseTarget, TargetRequest
from .base import AttackModule


class CORSMisconfigurationModule(AttackModule):
    """Probe CORS policies for arbitrary origin reflection, null origin, and prefix/suffix bypasses.

    OWASP: A05:2021 – Security Misconfiguration
    CWE: CWE-942 (Permissive Cross-Origin Resource Sharing Policy)
    """
    id = "cors"
    module_id = "MOD-ACTIVE-02"
    name = "CORS Misconfiguration Prober"
    category = "ACTIVE"
    description = (
        "Actively probes CORS policy enforcement using untrusted origin reflection, "
        "null origin, and domain substring bypasses to detect insecure credentialed access."
    )
    prerequisite: list[str] = []
    capabilities: list[str] = ["origin_fuzzing", "cors_header_analysis", "credential_leakage_verification"]
    owasp_category = "A05:2021 – Security Misconfiguration"
    cwe_id = "CWE-942"

    def execute(
        self,
        target: Union[BaseTarget, str],
        store: Optional[EvidenceStore] = None,
        scope: Optional[Scope] = None,
        gateway: Optional[NetworkGateway] = None,
        target_path: str = "/api/orders/101",
    ) -> AttackResult:
        """Execute active CORS security tests against the target endpoint.

        Args:
            target: Target URL string or BaseTarget implementation.
            store: Optional EvidenceStore instance.
            scope: Optional Scope configuration.
            gateway: Optional NetworkGateway instance for egress requests.
            target_path: Endpoint to probe for CORS configuration (defaults to '/api/orders/101').
        """
        evidence_store = store or EvidenceStore()
        effective_scope = scope or (gateway.scope if gateway else Scope())
        effective_gateway = gateway or NetworkGateway(scope=effective_scope)

        telemetry: list[Observation] = []
        collected_evidence: list[Evidence] = []

        base_url = target if isinstance(target, str) else target.base_url
        target_domain = urllib.parse.urlparse(base_url).hostname or "target.com"

        # Three bounded CORS test cases
        test_cases = [
            ("ORIGIN_REFLECTION", "https://attacker.example.com", "Test reflection of arbitrary untrusted third-party origin."),
            ("NULL_ORIGIN", "null", "Test handling of sandboxed iframe 'null' origin."),
            ("DOMAIN_BYPASS", f"https://{target_domain}.attacker.com", "Test regex prefix/suffix bypass on target domain name."),
        ]

        budget_exhausted = False
        error_message: Optional[str] = None

        for test_name, test_origin, test_desc in test_cases:
            if effective_scope.current_requests >= effective_scope.max_requests:
                budget_exhausted = True
                error_message = f"Request budget exhausted ({effective_scope.max_requests} max). CORS assessment incomplete."
                telemetry.append(Observation(
                    step="BUDGET_EXCEEDED",
                    action="REQUEST_BUDGET_EXHAUSTED",
                    details={"max_requests": effective_scope.max_requests, "completed_tests": len(collected_evidence)},
                ))
                break

            telemetry.append(Observation(
                step="CORS_PROBE",
                action=f"GET {target_path} (Origin: {test_origin})",
                details={"test_case": test_name, "origin": test_origin, "description": test_desc},
            ))

            req_headers = {
                "Origin": test_origin,
                "Accept": "application/json, text/plain, */*",
            }

            status_code, resp_headers, body_str = self._request(
                method="GET",
                target=target,
                path=target_path,
                headers=req_headers,
                gateway=effective_gateway,
                scope=effective_scope,
            )

            if status_code is None:
                continue

            # Capture CORS-specific response headers
            acao = resp_headers.get("access-control-allow-origin", "")
            acac = resp_headers.get("access-control-allow-credentials", "")
            obs_text = (
                f"CORS probe with Origin '{test_origin}' returned HTTP {status_code}. "
                f"ACAO: '{acao}', ACAC: '{acac}'."
            )

            ev = Evidence(
                id=evidence_store.next_id(),
                evidence_type="HTTP_CORS_PROBE",
                request_method="GET",
                request_path=target_path,
                request_headers=req_headers,
                request_body=None,
                response_status=status_code,
                response_headers=resp_headers,
                response_body=body_str[:1024] if body_str else None,
                authenticated_actor=None,
                resource_owner=None,
                observation=obs_text,
                assessment_id=getattr(evidence_store, "assessment_id", "default"),
            )
            stored_ev = evidence_store.add_evidence(ev)
            collected_evidence.append(stored_ev)

        # Deterministic finding validation
        findings = FindingValidator.validate_cors_misconfiguration(collected_evidence)
        for finding in findings:
            evidence_store.add_finding(finding)

        is_confirmed = any(f.status == FindingStatus.CONFIRMED for f in findings)
        if is_confirmed:
            status_str = "VULNERABILITY_CONFIRMED"
        elif any(f.status == FindingStatus.UNCONFIRMED for f in findings):
            status_str = "VULNERABILITY_UNCONFIRMED"
        elif budget_exhausted:
            status_str = "BUDGET_EXCEEDED"
        else:
            status_str = "VULNERABILITY_NOT_DETECTED"

        return AttackResult(
            attack_id=self.module_id,
            attack_name=self.name,
            success=is_confirmed,
            status=status_str,
            evidence=collected_evidence,
            findings=findings,
            telemetry=telemetry,
            error_message=error_message,
        )

    def run(
        self,
        target_url: str,
        scope: Optional[Scope] = None,
        store: Optional[EvidenceStore] = None,
    ) -> AttackResult:
        """Standard invocation contract compatibility wrapper."""
        return self.execute(target=target_url, store=store, scope=scope)

    def _request(
        self,
        method: str,
        target: Union[BaseTarget, str],
        path: str,
        headers: dict[str, str],
        gateway: NetworkGateway,
        scope: Scope,
    ) -> tuple[Optional[int], dict[str, str], str]:
        """Perform CORS probe respecting PolicyGate and NetworkGateway boundaries."""
        if isinstance(target, str):
            clean_base = target.rstrip("/")
            url = urllib.parse.urljoin(clean_base + "/", path.lstrip("/"))
            try:
                resp = gateway.execute_request(method=method, url=url, headers=headers)
                return resp.status_code, resp.headers, resp.body
            except NetworkGatewayError:
                return None, {}, ""

        elif isinstance(target, BaseTarget):
            parsed_base = urllib.parse.urlparse(target.base_url)
            domain = parsed_base.hostname or "localhost"
            decision = gateway.policy_gate.evaluate(
                action_id=f"{self.id}_{method.lower()}",
                target_path=path,
                target_domain=domain,
                prerequisites=self.prerequisite,
                satisfied_prerequisites=[],
                http_method=method,
            )
            if not decision.allowed:
                return None, {}, ""

            try:
                t_req = TargetRequest(method=method, path=path, headers=headers)
                t_resp = target.handle_request(t_req)
                body_val = t_resp.body
                body_str = json.dumps(body_val) if isinstance(body_val, (dict, list)) else str(body_val or "")
                return t_resp.status_code, dict(t_resp.headers), body_str
            except Exception:
                return None, {}, ""

        return None, {}, ""


if __name__ == "__main__":
    from raven.target.lab import VulnerableLabTarget
    mod = CORSMisconfigurationModule()
    target = VulnerableLabTarget()
    res = mod.execute(target)
    print(f"Module: {res.attack_name} | Success: {res.success} | Status: {res.status}")
    for f in res.findings:
        print(f"[{f.id}] {f.vulnerability_type} ({f.severity}) on {f.endpoint}")
