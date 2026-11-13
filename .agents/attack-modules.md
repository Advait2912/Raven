# Skill: Writing Attack/Assessment Modules

## Module Interface

Every attack module extends the `AttackModule` ABC in `attack/base.py`:

```python
class AttackModule(ABC):
    id: str                    # Unique ID: "headers", "cookies", "cors", "idor", "exposure", "tls"
    name: str                  # Human-readable name
    category: str              # "passive" or "active"
    description: str
    prerequisite: list[str]    # e.g. ["authenticated_session"]
    capabilities: list[str]
    requires_approval: bool    # If True, HumanOversightGate must approve before tamper step

    @abstractmethod
    def execute(self, target, store=None) -> AttackResult:
        pass
```

## V1 Modules (6 total)

| # | Module | Category | `requires_approval` | Requests | Status |
|---|--------|----------|---------------------|----------|--------|
| 1 | Security Headers Audit | passive | `False` | 1 GET | Not started |
| 2 | Cookie Security Audit | passive | `False` | 1 POST | Not started |
| 3 | CORS Misconfiguration | active | `False` | 2–3 | Not started |
| 4 | IDOR | active | `True` | 3 | Prototype built |
| 5 | Sensitive Data Exposure | active | `False` | 15–25 | Not started |
| 6 | TLS / HTTPS | passive | `False` | 2 | Not started |

## Finding State Model (5 states)

The current codebase uses binary confirmed/not-detected. The V1 spec requires:

```
NOT_TESTED → NOT_DETECTED      (module ran, all checks clean)
NOT_TESTED → UNCONFIRMED       (suspicious but incomplete proof)
NOT_TESTED → CONFIRMED         (deterministic validator fully satisfied)
UNCONFIRMED → CONFIRMED        (additional evidence satisfies validator)
UNCONFIRMED → INVALIDATED      (counter-evidence disproves)
CONFIRMED → INVALIDATED        (new evidence disproves; requires human review)
```

**Rule:** State transitions are made ONLY by `FindingValidator`, never by AI.

## Writing a New Module — Checklist

1. **Create module file** in `attack/` extending `AttackModule`
2. **Create a VulnerableLabTarget variant** (e.g., `HeadersVulnerableTarget`) for testing
3. **Add deterministic validation** in `raven/core/validator.py` for the new finding type
4. **Write tests** covering:
   - Unit: synthetic evidence → each expected finding state
   - Integration: VulnerableTarget → CONFIRMED
   - Integration: PatchedTarget → NOT_DETECTED
   - False positive: edge cases from Section 6.4 of the spec
5. **Add fallback template** in `FallbackEngine` before the module ships
6. **Register** the module in `AttackRegistry`

## Non-Negotiable Module Rules

1. **No test ever fires HTTP requests against real external hosts.** Use `VulnerableLabTarget` variants or `httpx.MockTransport`.
2. **All target responses pass through `RedactionPipeline` before storage.** Module code must not write raw responses to `EvidenceStore`.
3. **Active modules (`requires_approval=True`) must pause at `PENDING_APPROVAL`** and wait for `HumanOversightGate` approval before executing the tamper/probe step.
4. **Every evidence item must have a stable sequential ID** from `EvidenceStore.next_id()`.
5. **Modules must handle target errors gracefully** — a connection timeout or 5xx is `NOT_DETECTED` or `NOT_TESTED`, never a crash.

## IDOR-Specific Validation Rules (Strict)

The current IDOR validator is a prototype. The V1 spec requires:
- `CONFIRMED` needs ALL of: `E02.status == 200` AND `actor != owner` AND `owner` matches a known different user AND response body contains private fields (email, address, payment, PII)
- `UNCONFIRMED` if: `E02.status == 200` AND `actor != owner` BUT body is generic (no private fields)
- HTTP 200 alone is NOT proof — the body must demonstrate private data leakage

## Evidence Types by Module

| Module | Evidence Types |
|--------|---------------|
| Headers | `HTTP_HEADER_SET` |
| Cookies | `HTTP_COOKIE_ATTRIBUTES` |
| CORS | `HTTP_CORS_PROBE`, `HTTP_CORS_CREDENTIAL_PROBE` |
| IDOR | `HTTP_BASELINE_ACCESS`, `HTTP_TAMPER_ACCESS` |
| Exposure | `HTTP_PATH_PROBE` |
| TLS | `TLS_CERTIFICATE`, `HTTP_REDIRECT_CHECK` |
