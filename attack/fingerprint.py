# Technology Fingerprinting Assessment Module.
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


class TechnologyFingerprintModule(AttackModule):
    """Identify backend server banners, web frameworks, and client-side UI libraries.

    OWASP: A05:2021 – Security Misconfiguration
    CWE: CWE-200 (Information Exposure Through Server Headers)
    """
    id = "fingerprint"
    module_id = "MOD-PASSIVE-03"
    name = "Technology Fingerprinting"
    category = "PASSIVE"
    description = (
        "Passively analyzes HTTP response headers (Server, X-Powered-By, X-AspNet-Version) "
        "and HTML markup (generator meta tags, script paths, DOM markers) to profile the technology stack."
    )
    prerequisite: list[str] = []
    capabilities: list[str] = ["header_analysis", "html_signature_detection", "framework_fingerprinting"]
    owasp_category = "A05:2021 – Security Misconfiguration"
    cwe_id = "CWE-200"

    def execute(
        self,
        target: Union[BaseTarget, str],
        store: Optional[EvidenceStore] = None,
        scope: Optional[Scope] = None,
        gateway: Optional[NetworkGateway] = None,
        endpoints: Optional[list[str]] = None,
    ) -> AttackResult:
        """Execute technology stack fingerprinting.

        Args:
            target: Target URL string or BaseTarget implementation.
            store: Optional EvidenceStore instance.
            scope: Optional Scope configuration.
            gateway: Optional NetworkGateway instance for egress requests.
            endpoints: Optional list of endpoints to inspect (defaults to ['/']).
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
            if effective_scope.current_requests >= effective_scope.max_requests:
                budget_exhausted = True
                error_message = f"Request budget exhausted ({effective_scope.max_requests} max)."
                telemetry.append(Observation(
                    step="BUDGET_EXCEEDED",
                    action="REQUEST_BUDGET_EXHAUSTED",
                    details={"max_requests": effective_scope.max_requests},
                ))
                break

            telemetry.append(Observation(
                step="FINGERPRINT_PROBE",
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
                continue

            obs_text = (
                f"Fingerprint probe against {path} returned HTTP {status_code}. "
                f"Headers: {list(resp_headers.keys())}."
            )

            ev = Evidence(
                id=evidence_store.next_id(),
                evidence_type="HTTP_FINGERPRINT_PROBE",
                request_method="GET",
                request_path=path,
                request_headers={"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
                request_body=None,
                response_status=status_code,
                response_headers=resp_headers,
                response_body=body_str[:8192] if body_str else None,
                authenticated_actor=None,
                resource_owner=None,
                observation=obs_text,
                assessment_id=getattr(evidence_store, "assessment_id", "default"),
            )
            stored_ev = evidence_store.add_evidence(ev)
            collected_evidence.append(stored_ev)

        # Deterministic finding validation
        findings = FindingValidator.validate_technology_fingerprint(collected_evidence)
        for finding in findings:
            evidence_store.add_finding(finding)

        is_confirmed = any(f.status == FindingStatus.CONFIRMED for f in findings)
        if is_confirmed:
            status_str = "VULNERABILITY_CONFIRMED"
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
    mod = TechnologyFingerprintModule()
    target = VulnerableLabTarget()
    res = mod.execute(target)
    print(f"Module: {res.attack_name} | Success: {res.success} | Status: {res.status}")
    for f in res.findings:
        print(f"[{f.id}] {f.vulnerability_type} ({f.severity}) on {f.endpoint}")
