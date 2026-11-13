# Issue: Implement 5 V1 Assessment Modules (Headers, Disclosure, Fingerprint, CORS, Exposure)

**Labels:** `enhancement`, `modules`, `stage-2`  
**Assignee:** TBD  
**Epic:** Assessment Module Suite Expansion  
**Reference Spec:** `.agents/attack-modules.md`, `docs/RAVEN_V1_Technical_Specification.md` (Section 6)

---

## Objective

Expand RAVEN from the single IDOR vertical slice to the full suite of 6 V1 assessment modules. Implement the 5 remaining modules following the standard module interface, PolicyGate scope enforcement, and deterministic 5-state finding model.

---

## Architectural Requirements

Each module must inherit from `AttackModule` (in `attack/base.py`) or implement the standard contract:

```python
class BaseAssessmentModule(ABC):
    module_id: str
    module_name: str
    category: str        # "PASSIVE" or "ACTIVE"
    owasp_category: str  # e.g., "A05:2021-Security Misconfiguration"
    cwe_id: str          # e.g., "CWE-16"

    @abstractmethod
    def run(self, target_url: str, scope: Scope) -> AttackResult:
        ...
```

### Non-Negotiable Rules
1. **Network via NetworkGateway:** All outbound HTTP requests must pass through `NetworkGateway` and `PolicyGate` (import from `raven.core`).
2. **Evidence Grounding:** Every finding must cite one or more `evidence_ids` generated and stored in `EvidenceStore`.
3. **5-State Finding Lifecycle:** Modules must return findings with explicit `FindingStatus` (`CONFIRMED`, `UNCONFIRMED`, `NOT_DETECTED`). Never fabricate confidence or bypass `FindingValidator`.
4. **No Raw Secrets:** Rely on `EvidenceStore`'s automatic `RedactionPipeline` — never write unredacted bearer tokens or passwords to disk or logs.
5. **Standard Library / Zero Heavy Deps:** Use existing stdlib tools or light dependencies already specified in `requirements.txt`.

---

## Modules to Implement

### 1. `attack/headers.py` — Security Headers & Cookie Flags (Passive)
- **ID:** `MOD-PASSIVE-01`
- **CWE:** CWE-693 (Protection Mechanism Failure), CWE-614 (Sensitive Cookie in HTTPS Session Without 'Secure' Attribute)
- **Behavior:**
  - Performs single `GET` or `HEAD` request to target root and declared API endpoints.
  - Checks for presence and configuration of:
    - `Strict-Transport-Security` (HSTS)
    - `Content-Security-Policy` (CSP)
    - `X-Frame-Options`
    - `X-Content-Type-Options: nosniff`
    - `Referrer-Policy`
    - `Permissions-Policy`
  - Evaluates `Set-Cookie` flags (`Secure`, `HttpOnly`, `SameSite=Lax|Strict`).
- **Findings:** Emits `CONFIRMED` finding when critical headers are missing or insecure cookie attributes are observed.

### 2. `attack/disclosure.py` — Information Disclosure (Passive / Light Active)
- **ID:** `MOD-PASSIVE-02`
- **CWE:** CWE-200 (Exposure of Sensitive Information)
- **Behavior:**
  - Probes high-risk well-known paths:
    - `/.git/HEAD`, `/.git/config`
    - `/.env`, `/.env.local`, `/.env.production`
    - `/docker-compose.yml`, `/Dockerfile`
    - `/.DS_Store`, `/backup.sql`, `/dump.sql`
    - `/swagger.json`, `/openapi.json`, `/api-docs`
  - Verifies HTTP 200 response contains legitimate fingerprint signatures (e.g., `ref: refs/heads` for git, key-value pairs for env), not generic custom 200 HTML error pages.
- **Findings:** Emits `CONFIRMED` finding with request/response evidence proving exposure.

### 3. `attack/fingerprint.py` — Technology Fingerprinting (Passive)
- **ID:** `MOD-PASSIVE-03`
- **CWE:** CWE-200 (Information Exposure Through Server Headers)
- **Behavior:**
  - Inspects response headers (`Server`, `X-Powered-By`, `X-AspNet-Version`, etc.).
  - Inspects HTML body for framework signatures (generator meta tags, distinctive script paths).
  - Normalizes detected technology stack without invasive banner probing.

### 4. `attack/cors.py` — CORS Misconfiguration (Active)
- **ID:** `MOD-ACTIVE-02`
- **CWE:** CWE-942 (Permissive Cross-Origin Resource Sharing Policy)
- **Behavior:**
  - Sends requests with crafted `Origin` headers:
    1. Origin reflection test: `Origin: https://attacker.example.com`
    2. Null origin test: `Origin: null`
    3. Prefix/Suffix bypass test: `Origin: https://target.com.attacker.com`
  - Checks if response reflects the origin in `Access-Control-Allow-Origin` AND sets `Access-Control-Allow-Credentials: true`.
- **Findings:** Emits `CONFIRMED` only when credentialed origin reflection is verified with concrete evidence.

### 5. `attack/exposure.py` — Excessive Data Exposure (Active)
- **ID:** `MOD-ACTIVE-03`
- **CWE:** CWE-213 (Exposure of Sensitive Information Through Sentinel/API Responses)
- **Behavior:**
  - Compares authenticated client view requirements against raw API response payload.
  - Flags responses leaking internal fields: password hashes, reset tokens, full SSN, database IDs not needed by the view.
- **Findings:** Emits `CONFIRMED` when sensitive fields are verified in response bodies.

---

## Acceptance Criteria

- [ ] All 5 modules created in `attack/` with standardized class names and docstrings.
- [ ] Each module accepts `target_url` and `Scope` and honors `scope.max_requests`.
- [ ] Unit tests added under `tests/test_modules.py` testing each module with mock responses and local fixtures.
- [ ] All findings link valid `evidence_ids` in `EvidenceStore`.
- [ ] Zero CI regressions on Python 3.11/3.12 and Docker.
