# Comprehensive test suite for the five security assessment modules in RAVEN:
# 1. SecurityHeadersModule (attack/headers.py)
# 2. InformationDisclosureModule (attack/disclosure.py)
# 3. TechnologyFingerprintModule (attack/fingerprint.py)
# 4. CORSMisconfigurationModule (attack/cors.py)
# 5. ExcessiveDataExposureModule (attack/exposure.py)
# Cross-module tests: Scope enforcement, request budgeting, EvidenceStore redaction,
# and deterministic finding validation.

import json
from unittest.mock import MagicMock, patch
import pytest

from attack.cors import CORSMisconfigurationModule
from attack.disclosure import InformationDisclosureModule
from attack.exposure import ExcessiveDataExposureModule
from attack.fingerprint import TechnologyFingerprintModule
from attack.headers import SecurityHeadersModule
from attack.idor import IDORAttack
from raven.core.models import FindingStatus
from raven.core.network import NetworkGateway, NetworkGatewayError, NetworkResponse
from raven.core.policy import Scope
from raven.core.store import EvidenceStore
from raven.core.validator import FindingValidator
from raven.target.base import BaseTarget, TargetRequest, TargetResponse
from raven.target.lab import VulnerableLabTarget


class MockTarget(BaseTarget):
    """Configurable in-memory mock target for unit tests."""
    id = "mock_target"
    name = "Mock Test Target"

    def __init__(self, base_url: str = "http://localhost:8000", responses: dict | None = None) -> None:
        self.base_url = base_url
        self.responses: dict[tuple[str, str], TargetResponse] = responses or {}
        self.recorded_requests: list[TargetRequest] = []

    def set_response(self, method: str, path: str, status_code: int, headers: dict | None = None, body: any = None) -> None:
        self.responses[(method.upper(), path)] = TargetResponse(
            status_code=status_code,
            headers=headers or {},
            body=body,
        )

    def handle_request(self, req: TargetRequest) -> TargetResponse:
        self.recorded_requests.append(req)
        key = (req.method.upper(), req.path)
        if key in self.responses:
            return self.responses[key]
        # Fallback 404
        return TargetResponse(status_code=404, headers={"Content-Type": "application/json"}, body={"error": "Not Found"})

    def reset_state(self) -> None:
        self.recorded_requests.clear()


# ============================================================================
# MODULE 1: Security Headers & Cookie Flags Tests
# ============================================================================

def test_headers_all_secure_no_findings():
    """When all recommended security headers are present and valid, no findings are emitted."""
    target = MockTarget(base_url="https://localhost:8000")
    target.set_response(
        "GET", "/",
        status_code=200,
        headers={
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'nonce-rAnd0m'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Set-Cookie": "sessionid=xyz123; Secure; HttpOnly; SameSite=Strict",
        },
        body="<html>Secure</html>",
    )

    module = SecurityHeadersModule()
    store = EvidenceStore()
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/"])
    result = module.execute(target, store=store, scope=scope)

    assert result.success is False
    assert result.status == "VULNERABILITY_NOT_DETECTED"
    assert len(result.findings) == 0
    assert len(result.evidence) == 1
    assert result.evidence[0].response_status == 200


def test_headers_missing_all_emits_findings():
    """Missing headers on an HTTPS site emit confirmed findings for HSTS, CSP, XFO, XCTO, Referrer."""
    target = MockTarget(base_url="https://localhost:8000")
    target.set_response("GET", "/", status_code=200, headers={}, body="<html>Bare</html>")

    module = SecurityHeadersModule()
    store = EvidenceStore()
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/"])
    result = module.execute(target, store=store, scope=scope)

    assert result.success is True
    assert result.status == "VULNERABILITY_CONFIRMED"
    types = [f.vulnerability_type for f in result.findings]
    assert any("HSTS" in t for t in types)
    assert any("Content Security Policy" in t for t in types)
    assert any("Clickjacking" in t for t in types)
    assert any("X-Content-Type-Options" in t for t in types)
    assert any("Referrer-Policy" in t for t in types)

    # Every finding cites valid evidence ID
    for f in result.findings:
        assert len(f.evidence_ids) > 0
        assert store.get_evidence(f.evidence_ids[0]) is not None


def test_headers_http_missing_hsts_not_confirmed():
    """Missing HSTS on plain HTTP is not confirmed as a vulnerability."""
    target = MockTarget(base_url="http://localhost:8000")
    target.set_response(
        "GET", "/",
        status_code=200,
        headers={
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        },
        body="<html>HTTP</html>",
    )

    module = SecurityHeadersModule()
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/"])
    result = module.execute(target, scope=scope)

    hsts_findings = [f for f in result.findings if "HSTS" in f.vulnerability_type]
    assert len(hsts_findings) == 0


def test_headers_hsts_max_age_zero():
    """HSTS configured with max-age=0 is flagged as disabled."""
    target = MockTarget(base_url="https://localhost:8000")
    target.set_response(
        "GET", "/",
        status_code=200,
        headers={"Strict-Transport-Security": "max-age=0"},
        body="<html>Zero Max Age</html>",
    )

    module = SecurityHeadersModule()
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/"])
    result = module.execute(target, scope=scope)

    hsts_findings = [f for f in result.findings if "HSTS" in f.vulnerability_type]
    assert len(hsts_findings) == 1
    assert "Disabled" in hsts_findings[0].vulnerability_type or "max-age=0" in hsts_findings[0].vulnerability_type


def test_headers_csp_unsafe_inline():
    """CSP containing 'unsafe-inline' without nonce/hash is flagged as unsafe."""
    target = MockTarget(base_url="http://localhost:8000")
    target.set_response(
        "GET", "/",
        status_code=200,
        headers={"Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'"},
        body="<html>Unsafe CSP</html>",
    )

    module = SecurityHeadersModule()
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/"])
    result = module.execute(target, scope=scope)

    csp_findings = [f for f in result.findings if "Unsafe Content Security Policy" in f.vulnerability_type]
    assert len(csp_findings) == 1
    assert csp_findings[0].status == FindingStatus.CONFIRMED


def test_headers_xfo_superseded_by_csp_frame_ancestors():
    """When CSP contains 'frame-ancestors', missing X-Frame-Options is NOT flagged."""
    target = MockTarget(base_url="http://localhost:8000")
    target.set_response(
        "GET", "/",
        status_code=200,
        headers={
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        },
        body="<html>Frame Ancestors</html>",
    )

    module = SecurityHeadersModule()
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/"])
    result = module.execute(target, scope=scope)

    xfo_findings = [f for f in result.findings if "Clickjacking" in f.vulnerability_type]
    assert len(xfo_findings) == 0


def test_headers_insecure_cookie_flags():
    """Session cookies lacking Secure, HttpOnly, and SameSite trigger separate findings."""
    target = MockTarget(base_url="https://localhost:8000")
    target.set_response(
        "GET", "/",
        status_code=200,
        headers={"Set-Cookie": "session_id=insecure_token_abc"},
        body="<html>Insecure Cookie</html>",
    )

    module = SecurityHeadersModule()
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/"])
    result = module.execute(target, scope=scope)

    cookie_findings = [f for f in result.findings if "Cookie" in f.vulnerability_type]
    types = [f.vulnerability_type for f in cookie_findings]
    assert any("Secure" in t for t in types)
    assert any("HttpOnly" in t for t in types)
    assert any("SameSite" in t for t in types)


def test_headers_non_session_cookie_without_httponly_no_false_positive():
    """Non-session preference cookies (e.g., 'theme', 'lang') do not trigger missing HttpOnly findings."""
    target = MockTarget(base_url="http://localhost:8000")
    target.set_response(
        "GET", "/",
        status_code=200,
        headers={"Set-Cookie": "ui_theme=dark; SameSite=Lax"},
        body="<html>Theme Cookie</html>",
    )

    module = SecurityHeadersModule()
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/"])
    result = module.execute(target, scope=scope)

    httponly_findings = [f for f in result.findings if "HttpOnly" in f.vulnerability_type]
    assert len(httponly_findings) == 0


# ============================================================================
# MODULE 2: Information Disclosure Tests
# ============================================================================

def test_disclosure_exposed_env_confirmed():
    """Legitimate KEY=VALUE environment file returns CONFIRMED finding with redacted evidence."""
    target = MockTarget()
    target.set_response(
        "GET", "/.env",
        status_code=200,
        headers={"Content-Type": "text/plain"},
        body="DB_USER=admin\nDB_PASSWORD=supersecretpassword123\nAPI_KEY=AKIAIOSFODNN7EXAMPLE",
    )

    module = InformationDisclosureModule()
    store = EvidenceStore()
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/"])
    result = module.execute(target, store=store, scope=scope, custom_paths=["/.env"])

    assert result.success is True
    assert result.status == "VULNERABILITY_CONFIRMED"
    assert len(result.findings) == 1
    assert "Environment Secrets File" in result.findings[0].vulnerability_type
    assert result.findings[0].status == FindingStatus.CONFIRMED

    # Verify secret is redacted in stored evidence
    stored_ev = store.get_evidence(result.findings[0].evidence_ids[0])
    assert stored_ev is not None
    assert "supersecretpassword123" not in str(stored_ev.response_body)


def test_disclosure_exposed_git_head_confirmed():
    """Git HEAD containing 'ref: refs/heads/' confirms exposure."""
    target = MockTarget()
    target.set_response(
        "GET", "/.git/HEAD",
        status_code=200,
        headers={"Content-Type": "text/plain"},
        body="ref: refs/heads/main\n",
    )

    module = InformationDisclosureModule()
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/"])
    result = module.execute(target, scope=scope, custom_paths=["/.git/HEAD"])

    assert result.success is True
    assert "Git Repository Metadata" in result.findings[0].vulnerability_type


def test_disclosure_exposed_dockerfile_confirmed():
    """Dockerfile starting with FROM confirms exposure."""
    target = MockTarget()
    target.set_response(
        "GET", "/Dockerfile",
        status_code=200,
        headers={"Content-Type": "text/plain"},
        body="FROM python:3.12-slim\nWORKDIR /app\nRUN pip install -r requirements.txt",
    )

    module = InformationDisclosureModule()
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/"])
    result = module.execute(target, scope=scope, custom_paths=["/Dockerfile"])

    assert result.success is True
    assert "Container Build File" in result.findings[0].vulnerability_type


def test_disclosure_exposed_sql_dump_confirmed():
    """Database dump with CREATE TABLE confirms exposure."""
    target = MockTarget()
    target.set_response(
        "GET", "/dump.sql",
        status_code=200,
        headers={"Content-Type": "text/plain"},
        body="-- MySQL dump 10.13\nCREATE TABLE `users` (`id` int, `password` varchar(255));\nINSERT INTO `users` VALUES (1, 'hash');",
    )

    module = InformationDisclosureModule()
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/"])
    result = module.execute(target, scope=scope, custom_paths=["/dump.sql"])

    assert result.success is True
    assert "Database Backup Dump" in result.findings[0].vulnerability_type


def test_disclosure_exposed_openapi_confirmed():
    """Exposed OpenAPI json document confirms exposure."""
    target = MockTarget()
    target.set_response(
        "GET", "/openapi.json",
        status_code=200,
        headers={"Content-Type": "application/json"},
        body='{"openapi": "3.0.0", "info": {"title": "API"}, "paths": {"/admin": {}}}',
    )

    module = InformationDisclosureModule()
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/"])
    result = module.execute(target, scope=scope, custom_paths=["/openapi.json"])

    assert result.success is True
    assert "API Specification Document" in result.findings[0].vulnerability_type


def test_disclosure_exposed_ds_store_confirmed():
    """Binary .DS_Store file confirms exposure."""
    target = MockTarget()
    target.set_response(
        "GET", "/.DS_Store",
        status_code=200,
        headers={"Content-Type": "application/octet-stream"},
        body="\x00\x00\x00\x01Bud1\x00\x00\x10\x00",
    )

    module = InformationDisclosureModule()
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/"])
    result = module.execute(target, scope=scope, custom_paths=["/.DS_Store"])

    assert result.success is True
    assert ".DS_Store" in result.findings[0].vulnerability_type


def test_disclosure_custom_200_html_error_rejected():
    """An HTTP 200 response returning generic HTML error page is NOT confirmed as disclosure."""
    target = MockTarget()
    target.set_response(
        "GET", "/.env",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body="<!DOCTYPE html><html><head><title>404 Not Found</title></head><body>Page Not Found</body></html>",
    )

    module = InformationDisclosureModule()
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/"])
    result = module.execute(target, scope=scope, custom_paths=["/.env"])

    assert result.success is False
    assert result.status == "VULNERABILITY_NOT_DETECTED"
    assert len(result.findings) == 0


def test_disclosure_403_and_404_no_findings():
    """Paths returning 404 Not Found or 403 Forbidden do not produce vulnerability findings."""
    target = MockTarget()
    target.set_response("GET", "/.git/HEAD", status_code=404, headers={}, body="Not Found")
    target.set_response("GET", "/.env", status_code=403, headers={}, body="Access Denied")

    module = InformationDisclosureModule()
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/"])
    result = module.execute(target, scope=scope, custom_paths=["/.git/HEAD", "/.env"])

    assert result.success is False
    assert len(result.findings) == 0


# ============================================================================
# MODULE 3: Technology Fingerprinting Tests
# ============================================================================

def test_fingerprint_server_and_x_powered_by():
    """Server and X-Powered-By headers produce an informational fingerprint finding."""
    target = MockTarget()
    target.set_response(
        "GET", "/",
        status_code=200,
        headers={"Server": "nginx/1.24.0", "X-Powered-By": "Express"},
        body="<html>Express App</html>",
    )

    module = TechnologyFingerprintModule()
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/"])
    result = module.execute(target, scope=scope)

    assert result.success is True
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.severity == "INFO"
    assert "nginx" in finding.root_cause
    assert "Express" in finding.root_cause


def test_fingerprint_meta_generator():
    """HTML meta generator tag (e.g., WordPress) is detected."""
    target = MockTarget()
    target.set_response(
        "GET", "/",
        status_code=200,
        headers={},
        body='<html><head><meta name="generator" content="WordPress 6.4.2" /></head><body>WP</body></html>',
    )

    module = TechnologyFingerprintModule()
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/"])
    result = module.execute(target, scope=scope)

    assert result.success is True
    assert "WordPress" in result.findings[0].root_cause


def test_fingerprint_framework_dom_markers():
    """React and Angular markers in HTML are detected."""
    target = MockTarget()
    target.set_response(
        "GET", "/",
        status_code=200,
        headers={},
        body='<html><body><div id="root" data-reactroot=""><app-root ng-version="17.0.0"></app-root></div></body></html>',
    )

    module = TechnologyFingerprintModule()
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/"])
    result = module.execute(target, scope=scope)

    assert result.success is True
    assert "React" in result.findings[0].root_cause
    assert "Angular" in result.findings[0].root_cause


def test_fingerprint_unknown_no_findings():
    """Plain response without tech signatures produces no findings."""
    target = MockTarget()
    target.set_response("GET", "/", status_code=200, headers={}, body="<html>Plain static content</html>")

    module = TechnologyFingerprintModule()
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/"])
    result = module.execute(target, scope=scope)

    assert result.success is False
    assert result.status == "VULNERABILITY_NOT_DETECTED"
    assert len(result.findings) == 0


# ============================================================================
# MODULE 4: CORS Misconfiguration Tests
# ============================================================================

def test_cors_reflected_origin_with_credentials_confirmed():
    """Reflecting arbitrary untrusted origin with credentials=true triggers CONFIRMED HIGH finding."""
    target = MockTarget()
    target.set_response(
        "GET", "/api/orders/101",
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "https://attacker.example.com",
            "Access-Control-Allow-Credentials": "true",
            "Vary": "Origin",
        },
        body={"order_id": 101},
    )

    module = CORSMisconfigurationModule()
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/api/orders/"])
    result = module.execute(target, scope=scope, target_path="/api/orders/101")

    assert result.success is True
    assert result.status == "VULNERABILITY_CONFIRMED"
    reflected = [f for f in result.findings if "Arbitrary Origin Reflection with Credentials" in f.vulnerability_type]
    assert len(reflected) == 1
    assert reflected[0].severity == "HIGH"
    assert reflected[0].status == FindingStatus.CONFIRMED


def test_cors_null_origin_with_credentials_confirmed():
    """Reflecting origin 'null' with credentials=true triggers CONFIRMED HIGH finding."""
    target = MockTarget()

    def custom_handler(req: TargetRequest) -> TargetResponse:
        origin = req.headers.get("Origin", "")
        if origin == "null":
            return TargetResponse(
                status_code=200,
                headers={"Access-Control-Allow-Origin": "null", "Access-Control-Allow-Credentials": "true"},
                body={"data": "sensitive"},
            )
        return TargetResponse(status_code=200, headers={}, body={})

    target.handle_request = custom_handler

    module = CORSMisconfigurationModule()
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/api/orders/"])
    result = module.execute(target, scope=scope, target_path="/api/orders/101")

    assert result.success is True
    null_findings = [f for f in result.findings if "'null' Origin Permitted with Credentials" in f.vulnerability_type]
    assert len(null_findings) == 1
    assert null_findings[0].severity == "HIGH"


def test_cors_prefix_suffix_bypass_confirmed():
    """Allowing domain substring bypass with credentials triggers CONFIRMED finding."""
    target = MockTarget(base_url="http://target.com")

    def custom_handler(req: TargetRequest) -> TargetResponse:
        origin = req.headers.get("Origin", "")
        if "attacker.com" in origin:
            return TargetResponse(
                status_code=200,
                headers={"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"},
                body={"data": "leak"},
            )
        return TargetResponse(status_code=200, headers={}, body={})

    target.handle_request = custom_handler

    module = CORSMisconfigurationModule()
    scope = Scope(allowed_domains=["target.com"], allowed_paths=["/api/orders/"])
    result = module.execute(target, scope=scope, target_path="/api/orders/101")

    assert result.success is True
    bypass = [f for f in result.findings if "Origin Substring/Domain Bypass" in f.vulnerability_type]
    assert len(bypass) == 1


def test_cors_wildcard_with_credentials_invalid_unconfirmed():
    """Wildcard ACAO with credentials=true is invalid browser behavior and reported UNCONFIRMED."""
    target = MockTarget()
    target.set_response(
        "GET", "/api/orders/101",
        status_code=200,
        headers={"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"},
        body={"public": "data"},
    )

    module = CORSMisconfigurationModule()
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/api/orders/"])
    result = module.execute(target, scope=scope, target_path="/api/orders/101")

    invalid_wildcard = [f for f in result.findings if "Invalid Wildcard with Credentials" in f.vulnerability_type]
    assert len(invalid_wildcard) == 1
    assert invalid_wildcard[0].status == FindingStatus.UNCONFIRMED


def test_cors_reflected_origin_without_credentials_low():
    """Reflecting origin without credentials is LOW severity."""
    target = MockTarget()
    target.set_response(
        "GET", "/api/orders/101",
        status_code=200,
        headers={"Access-Control-Allow-Origin": "https://attacker.example.com"},
        body={"public": "data"},
    )

    module = CORSMisconfigurationModule()
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/api/orders/"])
    result = module.execute(target, scope=scope, target_path="/api/orders/101")

    nocred = [f for f in result.findings if "Arbitrary Origin Reflection without Credentials" in f.vulnerability_type]
    assert len(nocred) == 1
    assert nocred[0].severity == "LOW"


def test_cors_restrictive_configuration_no_findings():
    """Properly restricted or absent CORS headers produce no findings."""
    target = MockTarget()
    target.set_response("GET", "/api/orders/101", status_code=200, headers={}, body={"order_id": 101})

    module = CORSMisconfigurationModule()
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/api/orders/"])
    result = module.execute(target, scope=scope, target_path="/api/orders/101")

    assert result.success is False
    assert result.status == "VULNERABILITY_NOT_DETECTED"
    assert len(result.findings) == 0


# ============================================================================
# MODULE 5: Excessive Data Exposure Tests
# ============================================================================

def test_exposure_password_hash_and_tokens_confirmed():
    """Exposing password hashes and reset tokens triggers CRITICAL/HIGH findings with redacted evidence."""
    target = MockTarget()
    target.set_response(
        "GET", "/api/profile",
        status_code=200,
        headers={"Content-Type": "application/json"},
        body={
            "id": 101,
            "username": "alice",
            "password_hash": "$2b$12$e8Y6bFvR8DkK0p2ZzG4Kou1234567890abcdefghijklmnopq",
            "password_reset_token": "a1b2c3d4e5f67890abcdef1234567890",
            "social_security_number": "123-45-6789",
        },
    )

    module = ExcessiveDataExposureModule()
    store = EvidenceStore()
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/api/profile"])
    result = module.execute(target, store=store, scope=scope, endpoints=["/api/profile"])

    assert result.success is True
    assert result.status == "VULNERABILITY_CONFIRMED"
    assert len(result.findings) == 1
    assert result.findings[0].severity == "CRITICAL"
    assert "Password" in result.findings[0].vulnerability_type

    # Verify sensitive data is redacted in stored evidence
    stored_ev = store.get_evidence(result.findings[0].evidence_ids[0])
    assert stored_ev is not None
    assert "$2b$12$e8Y6bFvR8" not in str(stored_ev.response_body)


def test_exposure_masked_values_no_finding():
    """Masked or redacted values (e.g., '****', '[REDACTED]') do NOT produce findings."""
    target = MockTarget()
    target.set_response(
        "GET", "/api/profile",
        status_code=200,
        headers={"Content-Type": "application/json"},
        body={
            "id": 101,
            "username": "alice",
            "password_hash": "********************",
            "credit_card_number": "****-****-****-1234",
            "reset_token": None,
        },
    )

    module = ExcessiveDataExposureModule()
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/api/profile"])
    result = module.execute(target, scope=scope, endpoints=["/api/profile"])

    assert result.success is False
    assert result.status == "VULNERABILITY_NOT_DETECTED"
    assert len(result.findings) == 0


def test_exposure_public_ids_and_harmless_words_no_false_positive():
    """Harmless fields containing substrings like 'id', 'token_type' are not flagged."""
    target = MockTarget()
    target.set_response(
        "GET", "/api/account",
        status_code=200,
        headers={"Content-Type": "application/json"},
        body={
            "user_id": "usr_12345",
            "order_id": 999,
            "token_type": "Bearer",
            "password_updated_at": "2026-01-01T00:00:00Z",
            "is_password_set": True,
        },
    )

    module = ExcessiveDataExposureModule()
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/api/account"])
    result = module.execute(target, scope=scope, endpoints=["/api/account"])

    assert result.success is False
    assert len(result.findings) == 0


# ============================================================================
# CROSS-MODULE & POLICY INTEGRATION TESTS
# ============================================================================

def test_modules_obey_request_budget():
    """Modules must halt requests once Scope.max_requests budget is exhausted."""
    target = MockTarget()
    for path in InformationDisclosureModule.PROBE_PATHS:
        target.set_response("GET", path, status_code=404)

    # Budget allows only 3 requests, while disclosure module has 13 default paths
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/"], max_requests=3)
    module = InformationDisclosureModule()
    result = module.execute(target, scope=scope)

    assert result.status == "BUDGET_EXCEEDED"
    assert scope.current_requests == 3
    assert len(target.recorded_requests) == 3


def test_modules_reject_out_of_scope_target():
    """Requests targeting domains not in scope are blocked by PolicyGate."""
    target = MockTarget(base_url="http://evil.com")
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/"])

    module = SecurityHeadersModule()
    result = module.execute(target, scope=scope)

    assert len(target.recorded_requests) == 0
    assert len(result.evidence) == 0
    assert result.status == "VULNERABILITY_NOT_DETECTED"


def test_modules_evidence_ids_sequential_and_valid():
    """Every generated finding must reference valid sequential evidence IDs."""
    target = MockTarget()
    target.set_response("GET", "/.git/HEAD", status_code=200, body="ref: refs/heads/main\n")

    store = EvidenceStore()
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/"])
    module = InformationDisclosureModule()
    result = module.execute(target, store=store, scope=scope, custom_paths=["/.git/HEAD"])

    assert len(result.findings) == 1
    finding = result.findings[0]
    for ev_id in finding.evidence_ids:
        assert ev_id.startswith("E")
        ev = store.get_evidence(ev_id)
        assert ev is not None
        assert ev.id == ev_id


def test_standard_run_contract_compatibility():
    """All 5 modules expose run(target_url, scope) compatibility interface."""
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/"])

    headers_mod = SecurityHeadersModule()
    disc_mod = InformationDisclosureModule()
    fp_mod = TechnologyFingerprintModule()
    cors_mod = CORSMisconfigurationModule()
    exp_mod = ExcessiveDataExposureModule()

    for mod in (headers_mod, disc_mod, fp_mod, cors_mod, exp_mod):
        assert hasattr(mod, "run")
        assert callable(mod.run)
        assert hasattr(mod, "execute")
        assert callable(mod.execute)


def test_existing_idor_attack_unaffected():
    """Existing IDORAttack executes cleanly against VulnerableLabTarget without regressions."""
    idor = IDORAttack()
    lab = VulnerableLabTarget()
    result = idor.execute(lab)

    assert result.success is True
    assert result.status == "VULNERABILITY_CONFIRMED"
    assert len(result.findings) == 1
    assert result.findings[0].vulnerability_type == "Insecure Direct Object Reference (IDOR)"


def test_headers_invalid_values_and_unsafe_referrer():
    """Invalid XFO and unsafe Referrer-Policy values are flagged."""
    target = MockTarget()
    target.set_response(
        "GET", "/",
        status_code=200,
        headers={
            "X-Frame-Options": "ALLOW-FROM https://foo.com",
            "X-Content-Type-Options": "invalid_value",
            "Referrer-Policy": "unsafe-url",
        },
        body="<html>Headers Test</html>",
    )

    module = SecurityHeadersModule()
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/"])
    result = module.execute(target, scope=scope)

    types = [f.vulnerability_type for f in result.findings]
    assert any("Invalid X-Frame-Options" in t for t in types)
    assert any("X-Content-Type-Options" in t for t in types)
    assert any("Insecure Referrer-Policy" in t for t in types)


def test_headers_multiple_cookies_and_samesite_none_insecure():
    """SameSite=None without Secure is flagged."""
    target = MockTarget(base_url="http://localhost:8000")
    target.set_response(
        "GET", "/",
        status_code=200,
        headers={"Set-Cookie": "tracker_id=abc; SameSite=None"},
        body="<html>Cookies Test</html>",
    )

    module = SecurityHeadersModule()
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/"])
    result = module.execute(target, scope=scope)

    samesite_findings = [f for f in result.findings if "SameSite=None" in f.vulnerability_type]
    assert len(samesite_findings) == 1


def test_headers_empty_and_malformed_response():
    """Empty or malformed responses do not cause crashes."""
    target = MockTarget()
    target.set_response("GET", "/", status_code=500, headers={}, body="")

    module = SecurityHeadersModule()
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/"])
    result = module.execute(target, scope=scope)

    assert result.status in ("VULNERABILITY_CONFIRMED", "VULNERABILITY_NOT_DETECTED")


def test_disclosure_redirect_response():
    """A redirect response (301/302) on a probe path does NOT confirm disclosure."""
    target = MockTarget()
    target.set_response(
        "GET", "/.git/HEAD",
        status_code=302,
        headers={"Location": "/login"},
        body="Redirecting...",
    )

    module = InformationDisclosureModule()
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/"])
    result = module.execute(target, scope=scope, custom_paths=["/.git/HEAD"])

    assert result.success is False
    assert len(result.findings) == 0


def test_disclosure_oversized_response_bounded():
    """Large file disclosure responses are bounded to prevent memory exhaustion."""
    target = MockTarget()
    large_sql = "-- MySQL dump\nCREATE TABLE test (id int);\n" + ("A" * 100_000)
    target.set_response(
        "GET", "/dump.sql",
        status_code=200,
        headers={"Content-Type": "text/plain"},
        body=large_sql,
    )

    module = InformationDisclosureModule()
    store = EvidenceStore()
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/"])
    result = module.execute(target, store=store, scope=scope, custom_paths=["/dump.sql"])

    assert result.success is True
    stored_ev = store.get_evidence(result.findings[0].evidence_ids[0])
    # Evidence body must be capped at 4KB
    assert len(str(stored_ev.response_body)) <= 4096


def test_fingerprint_asset_paths_and_csrf():
    """WordPress asset paths and Django CSRF token inputs are fingerprinted."""
    target = MockTarget()
    target.set_response(
        "GET", "/",
        status_code=200,
        headers={},
        body='<html><link href="/wp-content/themes/style.css" /><input name="csrfmiddlewaretoken" value="abc" /><script src="/static/bootstrap.min.js"></script></html>',
    )

    module = TechnologyFingerprintModule()
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/"])
    result = module.execute(target, scope=scope)

    assert result.success is True
    root_cause = result.findings[0].root_cause
    assert "WordPress" in root_cause
    assert "Django" in root_cause
    assert "Bootstrap" in root_cause


def test_fingerprint_deduplication():
    """Duplicate fingerprint signatures across headers and HTML do not produce duplicate tech entries."""
    target = MockTarget()
    target.set_response(
        "GET", "/",
        status_code=200,
        headers={"Server": "Apache/2.4.52", "X-Powered-By": "PHP/8.1"},
        body='<html><meta name="generator" content="WordPress" /><link href="/wp-content/themes/a.css" /></html>',
    )

    module = TechnologyFingerprintModule()
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/"])
    result = module.execute(target, scope=scope)

    assert result.success is True
    # Ensure there is exactly 1 consolidated finding
    assert len(result.findings) == 1


def test_cors_malformed_response_handling():
    """Malformed or non-200 responses during CORS tests do not crash."""
    target = MockTarget()
    target.set_response("GET", "/api/orders/101", status_code=502, headers={}, body="Bad Gateway")

    module = CORSMisconfigurationModule()
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/api/orders/"])
    result = module.execute(target, scope=scope, target_path="/api/orders/101")

    assert result.success is False
    assert result.status == "VULNERABILITY_NOT_DETECTED"
    assert len(result.findings) == 0


def test_exposure_api_key_and_cc_confirmed():
    """API key and raw credit card exposure confirms HIGH severity finding."""
    target = MockTarget()
    target.set_response(
        "GET", "/api/account",
        status_code=200,
        headers={"Content-Type": "application/json"},
        body={
            "id": 1,
            "api_key": "live_sec_998877665544332211",
            "credit_card_number": "4111111111111111",
        },
    )

    module = ExcessiveDataExposureModule()
    store = EvidenceStore()
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/api/account"])
    result = module.execute(target, store=store, scope=scope, endpoints=["/api/account"])

    assert result.success is True
    assert result.findings[0].severity == "HIGH"
    types = result.findings[0].vulnerability_type
    assert "API Key" in types or "Payment Card" in types


def test_modules_connection_failure_resilience():
    """Simulated transport connection failure gracefully returns NOT_DETECTED without crashing."""
    module = SecurityHeadersModule()
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/"])

    # Target whose handler raises an exception
    broken_target = MockTarget()
    broken_target.handle_request = MagicMock(side_effect=RuntimeError("Connection reset by peer"))

    result = module.execute(broken_target, scope=scope)
    assert result.success is False
    assert result.status == "VULNERABILITY_NOT_DETECTED"

