# Excessive Data Exposure Assessment Module.
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


class ExcessiveDataExposureModule(AttackModule):
    """Audit API responses for unnecessary exposure of sensitive internal fields.

    OWASP: API3:2023 – Broken Object Property Level Authorization
    CWE: CWE-213 (Exposure of Sensitive Information Through Sentinel/API Responses)
    """
    id = "exposure"
    module_id = "MOD-ACTIVE-03"
    name = "Excessive Data Exposure Auditor"
    category = "ACTIVE"
    description = (
        "Inspects authorized and public API endpoints to detect responses leaking sensitive "
        "internal object properties such as password hashes, reset tokens, private API keys, and SSNs."
    )
    prerequisite: list[str] = []
    capabilities: list[str] = ["api_schema_analysis", "sensitive_field_detection", "object_property_inspection"]
    owasp_category = "API3:2023 – Broken Object Property Level Authorization"
    cwe_id = "CWE-213"

    DEFAULT_API_ENDPOINTS: list[str] = [
        "/api/orders/101",
        "/api/users/me",
        "/api/account",
        "/api/profile",
    ]

    def execute(
        self,
        target: Union[BaseTarget, str],
        store: Optional[EvidenceStore] = None,
        scope: Optional[Scope] = None,
        gateway: Optional[NetworkGateway] = None,
        endpoints: Optional[list[str]] = None,
        auth_headers: Optional[dict[str, str]] = None,
    ) -> AttackResult:
        """Execute excessive data exposure inspection across target API endpoints.

        Args:
            target: Target URL string or BaseTarget implementation.
            store: Optional EvidenceStore instance.
            scope: Optional Scope configuration.
            gateway: Optional NetworkGateway instance for egress requests.
            endpoints: Optional list of API paths to inspect.
            auth_headers: Optional authentication headers to include in requests.
        """
        evidence_store = store or EvidenceStore()
        effective_scope = scope or (gateway.scope if gateway else Scope())
        effective_gateway = gateway or NetworkGateway(scope=effective_scope)

        telemetry: list[Observation] = []
        collected_evidence: list[Evidence] = []
        target_paths = endpoints or self.DEFAULT_API_ENDPOINTS

        req_headers = dict(auth_headers or {})
        req_headers.setdefault("Accept", "application/json")

        budget_exhausted = False
        error_message: Optional[str] = None

        for path in target_paths:
            if effective_scope.current_requests >= effective_scope.max_requests:
                budget_exhausted = True
                error_message = f"Request budget exhausted ({effective_scope.max_requests} max). Exposure assessment incomplete."
                telemetry.append(Observation(
                    step="BUDGET_EXCEEDED",
                    action="REQUEST_BUDGET_EXHAUSTED",
                    details={"max_requests": effective_scope.max_requests, "completed_endpoints": len(collected_evidence)},
                ))
                break

            telemetry.append(Observation(
                step="DATA_EXPOSURE_PROBE",
                action=f"GET {path}",
                details={"target_path": path, "category": self.category},
            ))

            status_code, resp_headers, body_data = self._request(
                method="GET",
                target=target,
                path=path,
                headers=req_headers,
                gateway=effective_gateway,
                scope=effective_scope,
            )

            if status_code is None or status_code != 200:
                continue

            obs_text = f"API response from {path} returned HTTP 200 with structured data payload."

            ev = Evidence(
                id=evidence_store.next_id(),
                evidence_type="HTTP_DATA_EXPOSURE_PROBE",
                request_method="GET",
                request_path=path,
                request_headers=req_headers,
                request_body=None,
                response_status=status_code,
                response_headers=resp_headers,
                response_body=body_data,
                authenticated_actor="authenticated_user" if auth_headers else None,
                resource_owner=None,
                observation=obs_text,
                assessment_id=getattr(evidence_store, "assessment_id", "default"),
            )
            stored_ev = evidence_store.add_evidence(ev)
            collected_evidence.append(stored_ev)

        # Deterministic finding validation
        findings = FindingValidator.validate_excessive_data_exposure(collected_evidence)
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
    ) -> tuple[Optional[int], dict[str, str], Any]:
        """Perform request respecting PolicyGate and NetworkGateway boundaries."""
        if isinstance(target, str):
            clean_base = target.rstrip("/")
            url = urllib.parse.urljoin(clean_base + "/", path.lstrip("/"))
            try:
                resp = gateway.execute_request(method=method, url=url, headers=headers)
                try:
                    parsed_json = json.loads(resp.body)
                    return resp.status_code, resp.headers, parsed_json
                except (json.JSONDecodeError, ValueError):
                    return resp.status_code, resp.headers, resp.body
            except NetworkGatewayError:
                return None, {}, None

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
                return None, {}, None

            try:
                t_req = TargetRequest(method=method, path=path, headers=headers)
                t_resp = target.handle_request(t_req)
                return t_resp.status_code, dict(t_resp.headers), t_resp.body
            except Exception:
                return None, {}, None

        return None, {}, None


if __name__ == "__main__":
    from raven.target.lab import VulnerableLabTarget
    mod = ExcessiveDataExposureModule()
    target = VulnerableLabTarget()
    res = mod.execute(target)
    print(f"Module: {res.attack_name} | Success: {res.success} | Status: {res.status}")
    for f in res.findings:
        print(f"[{f.id}] {f.vulnerability_type} ({f.severity}) on {f.endpoint}")
