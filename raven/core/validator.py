import json
import re
from typing import Any, Optional
from .models import Evidence, Finding, FindingStatus


class FindingValidator:
    """Deterministic validator that confirms or rejects candidate findings."""

    @staticmethod
    def validate_idor(
        evidence_list: list[Evidence],
    ) -> Optional[Finding]:
        """Validate IDOR by checking if any evidence proves cross-user leakage."""
        confirming_evidence: list[str] = []

        for ev in evidence_list:
            # Condition 1: Must be HTTP 200 OK
            if ev.response_status != 200:
                continue

            # Condition 2: Must involve authenticated actor and distinct resource owner
            if ev.authenticated_actor and ev.resource_owner:
                if ev.authenticated_actor != ev.resource_owner:
                    confirming_evidence.append(ev.id)

        if not confirming_evidence:
            return None

        return Finding(
            id="FINDING-IDOR-01",
            vulnerability_type="Insecure Direct Object Reference (IDOR)",
            severity="HIGH",
            endpoint="/api/orders/{id}",
            evidence_ids=confirming_evidence,
            confirmed=True,
            status=FindingStatus.CONFIRMED,
            impact="Authenticated users can read sensitive order and personal data belonging to other accounts.",
            root_cause="Missing object-level access control check: the server queries by order_id without verifying owner_id == current_user.id.",
            remediation="Enforce ownership validation in the endpoint handler: verify `order.owner_id == authenticated_user.id` or return 403 Forbidden.",
            cwe_id="CWE-639",
        )

    @staticmethod
    def validate_security_headers(
        evidence_list: list[Evidence],
    ) -> list[Finding]:
        """Validate security headers and cookie flags across collected evidence."""
        findings: list[Finding] = []

        for ev in evidence_list:
            if ev.evidence_type not in ("HTTP_HEADER_SET", "HTTP_COOKIE_ATTRIBUTES", "HTTP_BASELINE_ACCESS"):
                continue

            headers = {k.lower(): str(v) for k, v in ev.response_headers.items()}
            is_https = ev.request_path.startswith("https://") or "https" in getattr(ev, "final_url", "").lower() or "https" in ev.observation.lower()

            # 1. Strict-Transport-Security (HSTS)
            if is_https:
                hsts = headers.get("strict-transport-security")
                if not hsts:
                    findings.append(Finding(
                        id=f"FINDING-HSTS-MISSING-{ev.id}",
                        vulnerability_type="Missing HTTP Strict Transport Security (HSTS)",
                        severity="MEDIUM",
                        endpoint=ev.request_path,
                        evidence_ids=[ev.id],
                        confirmed=True,
                        status=FindingStatus.CONFIRMED,
                        impact="Connections to the site over plaintext HTTP may not be upgraded automatically, enabling SSL stripping attacks.",
                        root_cause="Strict-Transport-Security header is not set in HTTP responses over HTTPS.",
                        remediation="Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` header to all HTTPS responses.",
                        cwe_id="CWE-693",
                    ))
                elif "max-age=0" in hsts:
                    findings.append(Finding(
                        id=f"FINDING-HSTS-INVALID-{ev.id}",
                        vulnerability_type="Disabled HTTP Strict Transport Security (HSTS max-age=0)",
                        severity="MEDIUM",
                        endpoint=ev.request_path,
                        evidence_ids=[ev.id],
                        confirmed=True,
                        status=FindingStatus.CONFIRMED,
                        impact="HSTS cache duration is set to zero, effectively disabling browser HSTS enforcement.",
                        root_cause="Strict-Transport-Security header specifies max-age=0.",
                        remediation="Set `Strict-Transport-Security: max-age=31536000; includeSubDomains`.",
                        cwe_id="CWE-693",
                    ))

            # 2. Content-Security-Policy (CSP)
            csp = headers.get("content-security-policy")
            if not csp:
                findings.append(Finding(
                    id=f"FINDING-CSP-MISSING-{ev.id}",
                    vulnerability_type="Missing Content Security Policy (CSP)",
                    severity="MEDIUM",
                    endpoint=ev.request_path,
                    evidence_ids=[ev.id],
                    confirmed=True,
                    status=FindingStatus.CONFIRMED,
                    impact="The browser cannot restrict origin sources for scripts, images, and other assets, increasing XSS risk.",
                    root_cause="Content-Security-Policy header is absent.",
                    remediation="Configure a restrictive Content-Security-Policy header defining trusted script-src and default-src directives.",
                    cwe_id="CWE-693",
                ))
            else:
                csp_lower = csp.lower()
                unsafe_inline = "'unsafe-inline'" in csp_lower
                unsafe_eval = "'unsafe-eval'" in csp_lower
                has_nonce = "nonce-" in csp_lower or "sha256-" in csp_lower
                if (unsafe_inline or unsafe_eval) and not has_nonce:
                    findings.append(Finding(
                        id=f"FINDING-CSP-UNSAFE-{ev.id}",
                        vulnerability_type="Unsafe Content Security Policy Directives",
                        severity="MEDIUM",
                        endpoint=ev.request_path,
                        evidence_ids=[ev.id],
                        confirmed=True,
                        status=FindingStatus.CONFIRMED,
                        impact="Use of 'unsafe-inline' or 'unsafe-eval' weakens CSP protections against cross-site scripting (XSS).",
                        root_cause=f"CSP contains unsafe directives without nonces or hashes: {csp}",
                        remediation="Remove 'unsafe-inline' and 'unsafe-eval' directives; use cryptographic nonces or hashes for scripts.",
                        cwe_id="CWE-693",
                    ))

            # 3. X-Frame-Options (Clickjacking defense, considering CSP frame-ancestors equivalence)
            csp_has_frame_ancestors = bool(csp and "frame-ancestors" in csp.lower())
            xfo = headers.get("x-frame-options")
            if not xfo and not csp_has_frame_ancestors:
                findings.append(Finding(
                    id=f"FINDING-XFO-MISSING-{ev.id}",
                    vulnerability_type="Missing Clickjacking Defense (X-Frame-Options / frame-ancestors)",
                    severity="LOW",
                    endpoint=ev.request_path,
                    evidence_ids=[ev.id],
                    confirmed=True,
                    status=FindingStatus.CONFIRMED,
                    impact="The application can be embedded into malicious third-party iframes, exposing users to clickjacking.",
                    root_cause="Neither X-Frame-Options nor CSP frame-ancestors directive is configured.",
                    remediation="Set `X-Frame-Options: DENY` or `SAMEORIGIN`, or include `frame-ancestors 'self'` in Content-Security-Policy.",
                    cwe_id="CWE-693",
                ))
            elif xfo and xfo.upper() not in ("DENY", "SAMEORIGIN"):
                findings.append(Finding(
                    id=f"FINDING-XFO-INVALID-{ev.id}",
                    vulnerability_type="Invalid X-Frame-Options Header Value",
                    severity="LOW",
                    endpoint=ev.request_path,
                    evidence_ids=[ev.id],
                    confirmed=True,
                    status=FindingStatus.CONFIRMED,
                    impact="Non-standard or deprecated X-Frame-Options value may be ignored by modern browsers.",
                    root_cause=f"X-Frame-Options set to invalid value: '{xfo}'.",
                    remediation="Set `X-Frame-Options: DENY` or `X-Frame-Options: SAMEORIGIN`.",
                    cwe_id="CWE-693",
                ))

            # 4. X-Content-Type-Options
            xcto = headers.get("x-content-type-options")
            if not xcto or xcto.lower().strip() != "nosniff":
                findings.append(Finding(
                    id=f"FINDING-XCTO-MISSING-{ev.id}",
                    vulnerability_type="Missing or Invalid X-Content-Type-Options Header",
                    severity="LOW",
                    endpoint=ev.request_path,
                    evidence_ids=[ev.id],
                    confirmed=True,
                    status=FindingStatus.CONFIRMED,
                    impact="Browsers may perform MIME-type sniffing on responses, potentially interpreting non-executable content as HTML/JavaScript.",
                    root_cause="X-Content-Type-Options header is missing or not set to 'nosniff'.",
                    remediation="Add `X-Content-Type-Options: nosniff` header to all responses.",
                    cwe_id="CWE-693",
                ))

            # 5. Referrer-Policy
            ref_pol = headers.get("referrer-policy")
            if not ref_pol:
                findings.append(Finding(
                    id=f"FINDING-REFERRER-MISSING-{ev.id}",
                    vulnerability_type="Missing Referrer-Policy Header",
                    severity="LOW",
                    endpoint=ev.request_path,
                    evidence_ids=[ev.id],
                    confirmed=True,
                    status=FindingStatus.CONFIRMED,
                    impact="Full URLs including path and query parameters may leak in the Referer header to external origins.",
                    root_cause="Referrer-Policy header is absent.",
                    remediation="Set `Referrer-Policy: strict-origin-when-cross-origin` or `no-referrer`.",
                    cwe_id="CWE-693",
                ))
            elif ref_pol.lower().strip() in ("unsafe-url", "no-referrer-when-downgrade"):
                findings.append(Finding(
                    id=f"FINDING-REFERRER-UNSAFE-{ev.id}",
                    vulnerability_type="Insecure Referrer-Policy Configuration",
                    severity="LOW",
                    endpoint=ev.request_path,
                    evidence_ids=[ev.id],
                    confirmed=True,
                    status=FindingStatus.CONFIRMED,
                    impact="The Referrer-Policy leaks sensitive URL query strings and paths across origin boundaries.",
                    root_cause=f"Referrer-Policy configured with permissive value: '{ref_pol}'.",
                    remediation="Set `Referrer-Policy: strict-origin-when-cross-origin` or `no-referrer`.",
                    cwe_id="CWE-693",
                ))

            # 6. Set-Cookie Flags (Secure, HttpOnly, SameSite)
            set_cookie_raw = headers.get("set-cookie", "")
            if set_cookie_raw:
                cookie_parts = set_cookie_raw.split(";")
                c_name = cookie_parts[0].split("=")[0].strip() if cookie_parts else "cookie"
                c_lower = set_cookie_raw.lower()

                # Session cookie identification
                session_markers = ("sess", "token", "jwt", "auth", "sid", "jsessionid", "phpsessid", "aspsessionid")
                is_session_cookie = any(m in c_name.lower() for m in session_markers)

                # Secure flag over HTTPS
                if is_https and "secure" not in c_lower:
                    findings.append(Finding(
                        id=f"FINDING-COOKIE-NO-SECURE-{ev.id}",
                        vulnerability_type=f"Cookie '{c_name}' Lacks 'Secure' Attribute",
                        severity="MEDIUM",
                        endpoint=ev.request_path,
                        evidence_ids=[ev.id],
                        confirmed=True,
                        status=FindingStatus.CONFIRMED,
                        impact="Cookie transmitted over HTTPS lacks the Secure flag, making it vulnerable to interception if transmitted over plain HTTP.",
                        root_cause=f"Set-Cookie header does not include the 'Secure' directive: {set_cookie_raw}",
                        remediation="Append `; Secure` to the Set-Cookie directive for all cookies on HTTPS sites.",
                        cwe_id="CWE-614",
                    ))

                # HttpOnly flag for session cookies
                if is_session_cookie and "httponly" not in c_lower:
                    findings.append(Finding(
                        id=f"FINDING-COOKIE-NO-HTTPONLY-{ev.id}",
                        vulnerability_type=f"Session Cookie '{c_name}' Lacks 'HttpOnly' Attribute",
                        severity="MEDIUM",
                        endpoint=ev.request_path,
                        evidence_ids=[ev.id],
                        confirmed=True,
                        status=FindingStatus.CONFIRMED,
                        impact="Session cookie can be accessed via client-side JavaScript (document.cookie), enabling session theft via XSS.",
                        root_cause=f"Session cookie '{c_name}' missing HttpOnly attribute: {set_cookie_raw}",
                        remediation="Append `; HttpOnly` to the Set-Cookie header for sensitive session and authentication cookies.",
                        cwe_id="CWE-1004",
                    ))

                # SameSite attribute
                if "samesite" not in c_lower:
                    findings.append(Finding(
                        id=f"FINDING-COOKIE-NO-SAMESITE-{ev.id}",
                        vulnerability_type=f"Cookie '{c_name}' Missing 'SameSite' Attribute",
                        severity="LOW",
                        endpoint=ev.request_path,
                        evidence_ids=[ev.id],
                        confirmed=True,
                        status=FindingStatus.CONFIRMED,
                        impact="Without explicit SameSite attribute, browser default behavior applies, increasing CSRF vulnerability risk.",
                        root_cause=f"Set-Cookie does not specify SameSite attribute: {set_cookie_raw}",
                        remediation="Set `; SameSite=Lax` or `; SameSite=Strict` on all cookies.",
                        cwe_id="CWE-1275",
                    ))
                elif "samesite=none" in c_lower and "secure" not in c_lower:
                    findings.append(Finding(
                        id=f"FINDING-COOKIE-SAMESITE-NONE-INSECURE-{ev.id}",
                        vulnerability_type=f"Cookie '{c_name}' Uses 'SameSite=None' Without 'Secure'",
                        severity="MEDIUM",
                        endpoint=ev.request_path,
                        evidence_ids=[ev.id],
                        confirmed=True,
                        status=FindingStatus.CONFIRMED,
                        impact="SameSite=None without Secure is rejected by modern browsers and permits cross-site leakage.",
                        root_cause=f"SameSite=None configured without Secure: {set_cookie_raw}",
                        remediation="Ensure any cookie using `SameSite=None` also includes the `Secure` attribute.",
                        cwe_id="CWE-1275",
                    ))

        return findings

    @staticmethod
    def validate_information_disclosure(
        evidence_list: list[Evidence],
    ) -> list[Finding]:
        """Validate sensitive file and endpoint exposure using content signatures."""
        findings: list[Finding] = []

        for ev in evidence_list:
            if ev.evidence_type not in ("HTTP_PATH_PROBE", "HTTP_DISCLOSURE_PROBE"):
                continue

            if ev.response_status != 200:
                continue

            body_str = str(ev.response_body or "")
            body_lower = body_str.lower()
            path = ev.request_path

            # Rejection of generic HTML error pages / SPA fallbacks
            is_html = (
                "<!doctype html" in body_lower
                or "<html" in body_lower
                or "<head" in body_lower
                or "<body" in body_lower
            )
            has_error_title = any(
                phrase in body_lower for phrase in ("404 not found", "page not found", "<title>error", "cannot get")
            )
            if is_html and has_error_title and not path.endswith((".html", "/")):
                continue

            confirmed_disclosure: Optional[tuple[str, str, str]] = None  # (file_type, impact, root_cause)

            # 1. Git repository HEAD & config
            if path.endswith("/.git/HEAD"):
                if body_str.startswith("ref: refs/heads/") or re.match(r"^[0-9a-f]{40}\n?$", body_str.strip()):
                    confirmed_disclosure = (
                        "Git Repository Metadata (.git/HEAD)",
                        "Attackers can download the entire source code repository, history, and embedded secrets.",
                        "The .git directory is accessible over HTTP without authorization restrictions.",
                    )
            elif path.endswith("/.git/config"):
                if "[core]" in body_str or "[remote " in body_str or "repositoryformatversion" in body_str:
                    confirmed_disclosure = (
                        "Git Configuration File (.git/config)",
                        "Exposes repository remote URLs, internal branches, and potentially repository credentials.",
                        "Web server allows public access to .git/config configuration file.",
                    )

            # 2. Environment configuration files (.env, .env.local, .env.production)
            elif any(path.endswith(env_f) for env_f in ("/.env", "/.env.local", "/.env.production")):
                if not is_html and re.search(r"^[A-Z0-9_]{2,}\s*=\s*.+", body_str, re.MULTILINE):
                    confirmed_disclosure = (
                        f"Environment Secrets File ({path})",
                        "Direct exposure of database credentials, API secret keys, tokens, and system configuration.",
                        "Production environment files deployed directly to web server document root without access controls.",
                    )

            # 3. Docker Compose & Dockerfile
            elif path.endswith("/docker-compose.yml"):
                if not is_html and ("services:" in body_str or "version:" in body_str):
                    confirmed_disclosure = (
                        "Docker Compose Specification (docker-compose.yml)",
                        "Exposes internal network layout, service dependencies, container environment variables, and ports.",
                        "Docker orchestration files deployed to public web root.",
                    )
            elif path.endswith("/Dockerfile"):
                if not is_html and re.search(r"^(FROM|RUN|CMD|ENTRYPOINT|ENV|WORKDIR)\s+", body_str, re.MULTILINE):
                    confirmed_disclosure = (
                        "Container Build File (Dockerfile)",
                        "Exposes base OS images, package installation instructions, internal build steps, and environment variables.",
                        "Dockerfile placed in accessible document root.",
                    )

            # 4. OS Metadata (.DS_Store)
            elif path.endswith("/.DS_Store"):
                if "Bud1" in body_str or body_str.startswith("\x00\x00\x00\x01Bud1"):
                    confirmed_disclosure = (
                        "macOS Directory Artifact (.DS_Store)",
                        "Leaks directory file lists, hidden system files, and structural names on the server.",
                        "Operating system metadata files uploaded to web root without exclusion rules.",
                    )

            # 5. Database dumps (.sql)
            elif path.endswith(("/backup.sql", "/dump.sql")):
                if not is_html and re.search(r"(CREATE\s+TABLE|INSERT\s+INTO|--\s*MySQL\s+dump|PostgreSQL\s+database\s+dump)", body_str, re.IGNORECASE):
                    confirmed_disclosure = (
                        f"Database Backup Dump ({path})",
                        "Critical exposure of raw database schemas, table definitions, and dumped application records.",
                        "Database backup files stored in publicly accessible web server folder.",
                    )

            # 6. OpenAPI / Swagger specs
            elif path.endswith(("/swagger.json", "/openapi.json", "/api-docs")):
                if ("\"openapi\":" in body_str or "\"swagger\":" in body_str or "\"paths\":" in body_str or
                        "openapi:" in body_str or "swagger:" in body_str):
                    confirmed_disclosure = (
                        f"API Specification Document ({path})",
                        "Reveals internal API routes, hidden administrative endpoints, query parameters, and schema models.",
                        "API documentation endpoints exposed without authentication or access controls.",
                    )

            if confirmed_disclosure:
                file_type, impact, root_cause = confirmed_disclosure
                findings.append(Finding(
                    id=f"FINDING-DISC-{ev.id}",
                    vulnerability_type=f"Information Disclosure: Exposed {file_type}",
                    severity="HIGH",
                    endpoint=path,
                    evidence_ids=[ev.id],
                    confirmed=True,
                    status=FindingStatus.CONFIRMED,
                    impact=impact,
                    root_cause=root_cause,
                    remediation=f"Block public HTTP access to `{path}` via server configuration rules (.htaccess, nginx location block) or remove sensitive files from web root.",
                    cwe_id="CWE-200",
                ))

        return findings

    @staticmethod
    def validate_technology_fingerprint(
        evidence_list: list[Evidence],
    ) -> list[Finding]:
        """Validate and consolidate technology fingerprint signatures into informational findings."""
        findings: list[Finding] = []
        detected_techs: dict[str, dict[str, Any]] = {}

        for ev in evidence_list:
            if ev.evidence_type not in ("HTTP_FINGERPRINT_PROBE", "HTTP_BASELINE_ACCESS", "HTTP_HEADER_SET"):
                continue

            headers = {k.lower(): str(v) for k, v in ev.response_headers.items()}
            body_str = str(ev.response_body or "")

            # 1. Header signatures
            server = headers.get("server")
            if server:
                detected_techs[f"Server: {server}"] = {
                    "source": "Header: Server",
                    "evidence_id": ev.id,
                    "confidence": 1.0,
                    "detail": server,
                }

            x_powered_by = headers.get("x-powered-by")
            if x_powered_by:
                detected_techs[f"Platform: {x_powered_by}"] = {
                    "source": "Header: X-Powered-By",
                    "evidence_id": ev.id,
                    "confidence": 1.0,
                    "detail": x_powered_by,
                }

            if "x-aspnet-version" in headers:
                detected_techs["Framework: ASP.NET"] = {
                    "source": "Header: X-AspNet-Version",
                    "evidence_id": ev.id,
                    "confidence": 1.0,
                    "detail": headers["x-aspnet-version"],
                }

            # 2. HTML meta generator signatures
            meta_match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']', body_str, re.IGNORECASE)
            if meta_match:
                gen = meta_match.group(1).strip()
                detected_techs[f"CMS/Generator: {gen}"] = {
                    "source": "HTML Meta Generator",
                    "evidence_id": ev.id,
                    "confidence": 1.0,
                    "detail": gen,
                }

            # 3. Frontend framework signatures
            if "data-reactroot" in body_str or "_reactListening" in body_str or "react.production.min.js" in body_str:
                detected_techs["Frontend: React"] = {
                    "source": "DOM / Script Markers",
                    "evidence_id": ev.id,
                    "confidence": 0.9,
                    "detail": "React DOM markers and runtime artifacts detected.",
                }

            if "ng-version" in body_str or "ng-app" in body_str or "<app-root>" in body_str:
                detected_techs["Frontend: Angular"] = {
                    "source": "DOM Attributes",
                    "evidence_id": ev.id,
                    "confidence": 0.9,
                    "detail": "Angular ng-version or app-root component detected.",
                }

            if "data-v-" in body_str or "vue.min.js" in body_str or "vue.js" in body_str:
                detected_techs["Frontend: Vue.js"] = {
                    "source": "Scoped CSS / Script Marker",
                    "evidence_id": ev.id,
                    "confidence": 0.85,
                    "detail": "Vue scoped CSS attribute or script detected.",
                }

            if "wp-content" in body_str or "wp-includes" in body_str:
                detected_techs["CMS: WordPress"] = {
                    "source": "Asset Paths",
                    "evidence_id": ev.id,
                    "confidence": 0.9,
                    "detail": "WordPress asset paths (wp-content / wp-includes) detected.",
                }

            if "csrfmiddlewaretoken" in body_str:
                detected_techs["Backend: Django"] = {
                    "source": "CSRF Token Input",
                    "evidence_id": ev.id,
                    "confidence": 0.85,
                    "detail": "Django csrfmiddlewaretoken form field detected.",
                }

            if "bootstrap.min.css" in body_str or "bootstrap.min.js" in body_str:
                detected_techs["UI: Bootstrap"] = {
                    "source": "Stylesheet / Script Link",
                    "evidence_id": ev.id,
                    "confidence": 0.9,
                    "detail": "Bootstrap framework library linked in HTML.",
                }

        if detected_techs:
            tech_summary = "; ".join(f"{tech} ({data['source']})" for tech, data in detected_techs.items())
            all_ev_ids = list({data["evidence_id"] for data in detected_techs.values()})
            findings.append(Finding(
                id="FINDING-FP-01",
                vulnerability_type="Technology Stack Fingerprint Disclosed",
                severity="INFO",
                endpoint=evidence_list[0].request_path if evidence_list else "/",
                evidence_ids=all_ev_ids,
                confirmed=True,
                status=FindingStatus.CONFIRMED,
                impact="Disclosing exact server banners, framework versions, and component names assists attackers in tailoring version-specific exploits.",
                root_cause=f"The application returns identifying headers or HTML signatures: {tech_summary}",
                remediation="Disable or customize Server and X-Powered-By response headers in web server configuration, and suppress meta generator tags.",
                cwe_id="CWE-200",
                confidence=1.0,
            ))

        return findings

    @staticmethod
    def validate_cors_misconfiguration(
        evidence_list: list[Evidence],
    ) -> list[Finding]:
        """Validate CORS policy configurations against origin reflection, null origin, and prefix/suffix tests."""
        findings_map: dict[tuple[str, str], Finding] = {}

        for ev in evidence_list:
            if ev.evidence_type not in ("HTTP_CORS_PROBE", "HTTP_CORS_CREDENTIAL_PROBE"):
                continue

            req_origin = ev.request_headers.get("origin") or ev.request_headers.get("Origin") or ""
            resp_headers = {k.lower(): str(v) for k, v in ev.response_headers.items()}
            acao = resp_headers.get("access-control-allow-origin")
            acac = resp_headers.get("access-control-allow-credentials", "").lower() == "true"

            if not acao:
                continue

            candidate: Optional[Finding] = None

            # Case 1: Reflected untrusted origin with credentials
            if acao == req_origin and req_origin == "https://attacker.example.com":
                if acac:
                    candidate = Finding(
                        id=f"FINDING-CORS-REFLECTED-CRED-{ev.id}",
                        vulnerability_type="CORS Misconfiguration: Arbitrary Origin Reflection with Credentials",
                        severity="HIGH",
                        endpoint=ev.request_path,
                        evidence_ids=[ev.id],
                        confirmed=True,
                        status=FindingStatus.CONFIRMED,
                        impact="Any malicious third-party website can make credentialed authenticated requests and read sensitive response data.",
                        root_cause="The server dynamically reflects the Origin header into Access-Control-Allow-Origin while setting Access-Control-Allow-Credentials: true.",
                        remediation="Maintain a strict server-side allowlist of trusted origins; do not dynamically reflect untrusted Origin values with credentials.",
                        cwe_id="CWE-942",
                    )
                else:
                    candidate = Finding(
                        id=f"FINDING-CORS-REFLECTED-NOCRED-{ev.id}",
                        vulnerability_type="CORS Misconfiguration: Arbitrary Origin Reflection without Credentials",
                        severity="LOW",
                        endpoint=ev.request_path,
                        evidence_ids=[ev.id],
                        confirmed=True,
                        status=FindingStatus.CONFIRMED,
                        impact="Untrusted origins can read unauthenticated API responses via cross-origin requests.",
                        root_cause=f"The server reflects arbitrary Origin '{req_origin}' into Access-Control-Allow-Origin.",
                        remediation="Do not reflect arbitrary Origin headers. Return an explicit allowlisted origin or omit ACAO for untrusted domains.",
                        cwe_id="CWE-942",
                    )

            # Case 2: Null origin reflection
            elif acao == "null" and req_origin == "null":
                if acac:
                    candidate = Finding(
                        id=f"FINDING-CORS-NULL-CRED-{ev.id}",
                        vulnerability_type="CORS Misconfiguration: 'null' Origin Permitted with Credentials",
                        severity="HIGH",
                        endpoint=ev.request_path,
                        evidence_ids=[ev.id],
                        confirmed=True,
                        status=FindingStatus.CONFIRMED,
                        impact="Sandboxed iframes, local file URI schemes, and data: URIs can make authenticated requests and read private responses.",
                        root_cause="Access-Control-Allow-Origin allows the 'null' origin combined with credentials.",
                        remediation="Never allow 'null' in Access-Control-Allow-Origin. Disallow cross-origin access from sandboxed origins.",
                        cwe_id="CWE-942",
                    )
                else:
                    candidate = Finding(
                        id=f"FINDING-CORS-NULL-NOCRED-{ev.id}",
                        vulnerability_type="CORS Misconfiguration: 'null' Origin Permitted",
                        severity="LOW",
                        endpoint=ev.request_path,
                        evidence_ids=[ev.id],
                        confirmed=True,
                        status=FindingStatus.CONFIRMED,
                        impact="Allows sandboxed frames without credentials to read unauthenticated responses.",
                        root_cause="Access-Control-Allow-Origin returns 'null'.",
                        remediation="Do not permit the 'null' origin in Access-Control-Allow-Origin.",
                        cwe_id="CWE-942",
                    )

            # Case 3: Prefix/Suffix bypass reflection with credentials
            elif acao == req_origin and ("attacker.com" in req_origin or "evil.com" in req_origin):
                if acac:
                    candidate = Finding(
                        id=f"FINDING-CORS-BYPASS-CRED-{ev.id}",
                        vulnerability_type="CORS Misconfiguration: Origin Substring/Domain Bypass with Credentials",
                        severity="HIGH",
                        endpoint=ev.request_path,
                        evidence_ids=[ev.id],
                        confirmed=True,
                        status=FindingStatus.CONFIRMED,
                        impact="Flawed regular expression or substring matching in CORS origin validation allows attacker domains to bypass origin checks.",
                        root_cause=f"Server validated Origin using insecure prefix/suffix matching: permitted '{req_origin}'.",
                        remediation=r"Use strict exact domain matching or properly anchored regular expressions (`^https://(.*\.)?example\.com$`).",
                        cwe_id="CWE-942",
                    )

            # Case 4: Wildcard with credentials (Invalid configuration per CORS specification)
            elif acao == "*" and acac:
                candidate = Finding(
                    id=f"FINDING-CORS-INVALID-WILDCARD-{ev.id}",
                    vulnerability_type="CORS Misconfiguration: Invalid Wildcard with Credentials",
                    severity="LOW",
                    endpoint=ev.request_path,
                    evidence_ids=[ev.id],
                    confirmed=False,
                    status=FindingStatus.UNCONFIRMED,
                    impact="Modern browsers reject responses combining Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true, but configuration indicates flawed intent.",
                    root_cause="Server attempts to allow wildcard origin alongside credentials.",
                    remediation="Explicitly specify authorized origins when credentials are required.",
                    cwe_id="CWE-942",
                )

            if candidate:
                key = (candidate.vulnerability_type, candidate.endpoint)
                if key not in findings_map:
                    findings_map[key] = candidate
                else:
                    for eid in candidate.evidence_ids:
                        if eid not in findings_map[key].evidence_ids:
                            findings_map[key].evidence_ids.append(eid)

        return list(findings_map.values())

    @staticmethod
    def validate_excessive_data_exposure(
        evidence_list: list[Evidence],
    ) -> list[Finding]:
        """Validate API responses for unnecessary or dangerous exposure of sensitive fields."""
        findings: list[Finding] = []

        sensitive_key_patterns = [
            (re.compile(r"(?i)^(.*_)?(password_hash|hashed_password|password|passwd)(_.*)?$"), "Password / Password Hash", "CRITICAL"),
            (re.compile(r"(?i)^(.*_)?(reset_token|password_reset_token)(_.*)?$"), "Account Password Reset Token", "HIGH"),
            (re.compile(r"(?i)^(.*_)?(api_?key|secret_?key|auth_?token|access_?token|refresh_?token|private_?key)(_.*)?$"), "API Key / Auth Secret", "HIGH"),
            (re.compile(r"(?i)^(.*_)?(ssn|social_security_number)(_.*)?$"), "Social Security Number (SSN)", "HIGH"),
            (re.compile(r"(?i)^(.*_)?(credit_card_number|card_number|cvv|cvc)(_.*)?$"), "Payment Card Number / CVV", "HIGH"),
        ]

        # False-positive filters for harmless metadata
        harmless_substrings = ("token_type", "password_updated_at", "password_reset_url", "has_token", "is_password_set")

        for ev in evidence_list:
            if ev.response_status != 200:
                continue

            body = ev.response_body
            if not body:
                continue

            def scan_structure(data: Any, path_prefix: str = "") -> list[tuple[str, str, str, str]]:
                results: list[tuple[str, str, str, str]] = []  # (field_name, field_type, severity, sample_summary)

                if isinstance(data, dict):
                    for k, v in data.items():
                        k_str = str(k)
                        current_path = f"{path_prefix}.{k_str}" if path_prefix else k_str

                        # Check harmless substrings
                        if any(h in k_str.lower() for h in harmless_substrings):
                            continue

                        # Check if key matches sensitive patterns
                        matched_rule = None
                        for regex, f_type, sev in sensitive_key_patterns:
                            if regex.match(k_str):
                                matched_rule = (f_type, sev)
                                break

                        if matched_rule:
                            f_type, sev = matched_rule
                            v_str = str(v).strip()

                            # Masked by target application (harmless)
                            is_target_masked = (
                                v is None
                                or v is False
                                or v == ""
                                or v_str.startswith("****")
                                or v_str in ("[REDACTED]", "[MASKED]", "REDACTED", "null")
                                or (len(v_str) > 0 and all(c == "*" for c in v_str))
                            )
                            if not is_target_masked and len(v_str) > 0:
                                results.append((current_path, f_type, sev, f"Field '{current_path}' contains active value ({len(v_str)} chars)."))
                        else:
                            results.extend(scan_structure(v, current_path))

                elif isinstance(data, list):
                    for idx, item in enumerate(data):
                        results.extend(scan_structure(item, f"{path_prefix}[{idx}]"))

                return results

            leaked_fields = scan_structure(body)

            if leaked_fields:
                field_names = [f[0] for f in leaked_fields]
                max_sev = "CRITICAL" if any(f[2] == "CRITICAL" for f in leaked_fields) else "HIGH"
                types_summary = ", ".join(sorted({f[1] for f in leaked_fields}))

                findings.append(Finding(
                    id=f"FINDING-EXP-{ev.id}",
                    vulnerability_type=f"Excessive Data Exposure: Sensitive Fields Disclosed ({types_summary})",
                    severity=max_sev,
                    endpoint=ev.request_path,
                    evidence_ids=[ev.id],
                    confirmed=True,
                    status=FindingStatus.CONFIRMED,
                    impact="API responses return sensitive internal fields that client applications do not need, enabling account compromise or data leaks.",
                    root_cause=f"The API serializer returns full object models without excluding sensitive properties: {', '.join(field_names)}.",
                    remediation="Apply Data Transfer Objects (DTOs) or field projection filters in API controllers to restrict serialization to authorized view fields.",
                    cwe_id="CWE-213",
                ))

        return findings
