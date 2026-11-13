# Security Headers & Cookie Flags Assessment Module.
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


class SecurityHeadersModule(AttackModule):
    """Audit security response headers and cookie security attributes.

    OWASP: A05:2021 – Security Misconfiguration
    CWE: CWE-693 (Protection Mechanism Failure), CWE-614 (Sensitive Cookie in HTTPS Without 'Secure')
    """
    id = "headers"
    module_id = "MOD-PASSIVE-01"
    name = "Security Headers & Cookie Flags Audit"
    category = "PASSIVE"
    description = (
        "Inspects HTTP response headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, "
        "Referrer-Policy, Permissions-Policy) and Set-Cookie security flags (Secure, HttpOnly, SameSite)."
    )
    prerequisite: list[str] = []
    capabilities: list[str] = ["header_inspection", "cookie_attribute_audit"]
    owasp_category = "A05:2021 – Security Misconfiguration"
    cwe_id = "CWE-693"

    def execute(
        self,
        target: Union[BaseTarget, str],
        store: Optional[EvidenceStore] = None,
        scope: Optional[Scope] = None,
        gateway: Optional[NetworkGateway] = None,
        endpoints: Optional[list[str]] = None,
    ) -> AttackResult:
        """Execute passive security headers and cookie flag inspection.

        Args:
            target: Target URL string or BaseTarget implementation.
            store: Optional EvidenceStore instance.
            scope: Optional Scope configuration.
            gateway: Optional NetworkGateway instance for egress requests.
            endpoints: Optional list of specific endpoints to inspect (defaults to ['/']).
        """
        evidence_store = store or EvidenceStore()
        effective_scope = scope or (gateway.scope if gateway else Scope())
        effective_gateway = gateway or NetworkGateway(scope=effective_scope)

        telemetry: list[Observation] = []
        collected_evidence: list[Evidence] = []
        target_paths = endpoints or ["/"]

        budget_exhausted = False
        error_message: Optional[str] = None

        for path in target_paths:
            telemetry.append(Observation(
                step="HEADER_INSPECTION_PROBE",
                action=f"GET {path}",
                details={"target_path": path, "category": self.category},
            ))

            status_code, resp_headers, body_str = self._request(
                method="GET",
                target=target,
                path=path,
                gateway=effective_gateway,
                scope=effective_scope,
            )

            if status_code is None:
                # Request was rejected by policy or budget exhausted
                if effective_scope.current_requests >= effective_scope.max_requests:
                    budget_exhausted = True
                    error_message = f"Request budget exceeded ({effective_scope.max_requests} max)."
                    telemetry.append(Observation(
                        step="BUDGET_EXCEEDED",
                        action="REQUEST_BUDGET_EXHAUSTED",
                        details={"max_requests": effective_scope.max_requests},
                    ))
                    break
                continue

            # Record empirical evidence
            base_url = target if isinstance(target, str) else target.base_url
            is_https = base_url.lower().startswith("https")
            obs_detail = (
                f"Inspected HTTP response headers from {path}. "
                f"Status: {status_code}, Headers present: {len(resp_headers)}."
                + (" (HTTPS context)" if is_https else " (HTTP context)")
            )

            ev = Evidence(
                id=evidence_store.next_id(),
                evidence_type="HTTP_HEADER_SET",
                request_method="GET",
                request_path=path,
                request_headers={"Accept": "*/*"},
                request_body=None,
                response_status=status_code,
                response_headers=resp_headers,
                response_body=body_str[:1024] if body_str else None,
                authenticated_actor=None,
                resource_owner=None,
                observation=obs_detail,
                assessment_id=getattr(evidence_store, "assessment_id", "default"),
            )
            stored_ev = evidence_store.add_evidence(ev)
            collected_evidence.append(stored_ev)

        # Deterministic finding validation
        findings = FindingValidator.validate_security_headers(collected_evidence)
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
        gateway: NetworkGateway,
        scope: Scope,
    ) -> tuple[Optional[int], dict[str, str], str]:
        """Perform request respecting PolicyGate and NetworkGateway boundaries."""
        if isinstance(target, str):
            clean_base = target.rstrip("/")
            url = urllib.parse.urljoin(clean_base + "/", path.lstrip("/"))
            try:
                resp = gateway.execute_request(method=method, url=url)
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
                t_req = TargetRequest(method=method, path=path, headers={"Accept": "*/*"})
                t_resp = target.handle_request(t_req)
                body_val = t_resp.body
                body_str = json.dumps(body_val) if isinstance(body_val, (dict, list)) else str(body_val or "")
                return t_resp.status_code, dict(t_resp.headers), body_str
            except Exception:
                return None, {}, ""

        return None, {}, ""


if __name__ == "__main__":
    from raven.target.lab import VulnerableLabTarget
    mod = SecurityHeadersModule()
    target = VulnerableLabTarget()
    res = mod.execute(target)
    print(f"Module: {res.attack_name} | Success: {res.success} | Status: {res.status}")
    for f in res.findings:
        print(f"[{f.id}] {f.vulnerability_type} ({f.severity}) on {f.endpoint}")
