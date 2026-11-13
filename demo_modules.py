"""Demo script to run and inspect all 5 RAVEN assessment modules in action.

Usage:
    PYTHONPATH=. python demo_modules.py
"""

from attack.cors import CORSMisconfigurationModule
from attack.disclosure import InformationDisclosureModule
from attack.exposure import ExcessiveDataExposureModule
from attack.fingerprint import TechnologyFingerprintModule
from attack.headers import SecurityHeadersModule
from raven.core.policy import Scope
from raven.core.store import EvidenceStore
from raven.target.base import BaseTarget, TargetRequest, TargetResponse


class DemoVulnerableTarget(BaseTarget):
    """Simulated web service with intentional misconfigurations across all 5 categories."""
    id = "demo_target"
    name = "Demo Vulnerable Target API"
    base_url = "https://localhost:8000"

    def handle_request(self, req: TargetRequest) -> TargetResponse:
        path = req.path
        origin = req.headers.get("Origin", "")

        # 1. Root: Insecure headers, weak CSP, insecure cookie, exposed tech banners
        if path == "/":
            return TargetResponse(
                status_code=200,
                headers={
                    "Server": "nginx/1.24.0",
                    "X-Powered-By": "Express",
                    "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'",
                    "Set-Cookie": "session_id=secret_sess_abc123; Path=/",
                },
                body='<html><head><meta name="generator" content="WordPress 6.4.2" /></head><body><div id="root" data-reactroot=""><h1>Demo App</h1></div></body></html>',
            )

        # 2. Exposed sensitive environment secrets
        elif path == "/.env":
            return TargetResponse(
                status_code=200,
                headers={"Content-Type": "text/plain"},
                body="DB_USER=postgres\nDB_PASSWORD=super_secret_db_pass_123!\nAPI_SECRET=sk_live_abcdef123456\n",
            )

        # 3. User profile endpoint leaking credentials & PII, reflecting arbitrary origins
        elif path == "/api/user/profile":
            return TargetResponse(
                status_code=200,
                headers={
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": origin if origin else "https://localhost:8000",
                    "Access-Control-Allow-Credentials": "true",
                },
                body={
                    "id": 42,
                    "username": "admin",
                    "email": "admin@example.com",
                    "password_hash": "$2b$12$e8Y6bFvR8DkK0p2ZzG4Kou1234567890abcdefghijklmnopq",
                    "password_reset_token": "a1b2c3d4e5f67890abcdef1234567890",
                    "api_key": "live_key_998877665544332211",
                    "social_security_number": "123-45-6789",
                },
            )

        return TargetResponse(status_code=404, headers={"Content-Type": "application/json"}, body={"error": "Not Found"})

    def reset_state(self) -> None:
        pass


def run_demo() -> None:
    print("=" * 70)
    print(" RAVEN Security Assessment Engine - 5 Modules Live Demo")
    print("=" * 70)

    target = DemoVulnerableTarget()
    scope = Scope(allowed_domains=["localhost"], allowed_paths=["/"])
    store = EvidenceStore()

    # Module 1: Security Headers & Cookies
    print("\n[+] 1. Running Security Headers Audit (MOD-PASSIVE-01)...")
    hdr_mod = SecurityHeadersModule()
    hdr_res = hdr_mod.execute(target, store=store, scope=scope, endpoints=["/"])
    print(f"    Status: {hdr_res.status} (Success: {hdr_res.success})")
    for f in hdr_res.findings:
        print(f"    -> [{f.severity}] {f.vulnerability_type}")

    # Module 2: Information Disclosure
    print("\n[+] 2. Running Information Disclosure Prober (MOD-PASSIVE-02)...")
    disc_mod = InformationDisclosureModule()
    disc_res = disc_mod.execute(target, store=store, scope=scope, custom_paths=["/.env", "/.git/HEAD"])
    print(f"    Status: {disc_res.status} (Success: {disc_res.success})")
    for f in disc_res.findings:
        print(f"    -> [{f.severity}] {f.vulnerability_type} at {f.endpoint}")

    # Module 3: Technology Fingerprinting
    print("\n[+] 3. Running Technology Fingerprinting (MOD-PASSIVE-03)...")
    fp_mod = TechnologyFingerprintModule()
    fp_res = fp_mod.execute(target, store=store, scope=scope, endpoints=["/"])
    print(f"    Status: {fp_res.status} (Success: {fp_res.success})")
    for f in fp_res.findings:
        print(f"    -> [{f.severity}] {f.vulnerability_type}")
        print(f"       Details: {f.root_cause}")

    # Module 4: CORS Misconfiguration
    print("\n[+] 4. Running CORS Misconfiguration Prober (MOD-ACTIVE-02)...")
    cors_mod = CORSMisconfigurationModule()
    cors_res = cors_mod.execute(target, store=store, scope=scope, target_path="/api/user/profile")
    print(f"    Status: {cors_res.status} (Success: {cors_res.success})")
    for f in cors_res.findings:
        print(f"    -> [{f.severity}] {f.vulnerability_type}")

    # Module 5: Excessive Data Exposure
    print("\n[+] 5. Running Excessive Data Exposure Auditor (MOD-ACTIVE-03)...")
    exp_mod = ExcessiveDataExposureModule()
    exp_res = exp_mod.execute(target, store=store, scope=scope, endpoints=["/api/user/profile"])
    print(f"    Status: {exp_res.status} (Success: {exp_res.success})")
    for f in exp_res.findings:
        print(f"    -> [{f.severity}] {f.vulnerability_type}")
        print(f"       Root cause: {f.root_cause}")

    # Verify Redaction in EvidenceStore
    print("\n" + "=" * 70)
    print(" EvidenceStore & Automatic Redaction Verification")
    print("=" * 70)
    print("Raw secrets returned by target vs Redacted values stored in evidence:\n")
    for ev in store.get_all_evidence():
        if ev.evidence_type in ("HTTP_PATH_PROBE", "HTTP_DATA_EXPOSURE_PROBE"):
            print(f"[{ev.id}] {ev.request_method} {ev.request_path}")
            print(f"     Status: {ev.response_status}")
            print(f"     Stored Payload: {ev.response_body}\n")


if __name__ == "__main__":
    run_demo()
