# Skill: Testing Strategy & CI/CD Pipeline

## Current Test Suite (30 passing tests)

| File | Tests | Covers |
|------|-------|--------|
| `tests/test_idor.py` | 2 | IDOR attack success on vulnerable target, failure on patched target |
| `tests/test_policy.py` | 3 | PolicyGate allow, domain scope rejection, prerequisite rejection |
| `tests/test_routes.py` | 3 | DemoController full vulnerable run, full patched run, 3-step patched run |
| `tests/test_security.py` | 18 | Out-of-scope domains (6), path traversal/spoofing (8), budget enforcement, false-positive prevention, unauthenticated/unsupported methods, store isolation + fail-closed controller |
| `tests/test_target.py` | 4 | Lab target health, auth success, IDOR vulnerability, remediation patch |

## V1 Test Categories (from spec Section 15)

```
tests/
├── unit/
│   ├── test_validators_*.py         # FindingValidator for each module
│   ├── test_redaction.py            # RedactionPipeline patterns + fail-closed
│   ├── test_trust_*.py              # Each Trust Layer component
│   └── test_network_gateway.py      # Private IP blocking, DNS mocking
├── integration/
│   ├── test_modules.py              # Modules vs benchmark VulnerableLabTargets
│   ├── test_lifecycle.py            # Assessment lifecycle (create → run → complete)
│   └── test_student_replay.py       # Student step-through replay
├── security/
│   ├── test_scope.py                # PolicyGate + NetworkGateway enforcement
│   ├── test_prompt_injection.py     # Adversarial content in target responses
│   ├── test_redaction_integration.py # Secrets never reach SQLite
│   └── test_network_safety.py       # SSRF, DNS rebinding, private IP
└── evaluation/
    ├── test_finding_reliability.py   # FPR, FNR against benchmark targets
    └── test_ai_reliability.py        # Unsupported claims, citation accuracy, consistency
```

## Mandatory Test Rules

1. **No test fires HTTP requests against real external hosts.** Use `VulnerableLabTarget` variants or `httpx.MockTransport`.
2. **RedactionPipeline tests use synthetic secrets** matching real-world patterns.
3. **Evaluation harness tests run against all 9 benchmark targets.**
4. **AuditLogger tests verify entries exist** without containing raw sensitive values.
5. **All tests must pass before merge to `main`.**

## Current CI/CD Pipeline

### CI (`.github/workflows/ci.yml`)

Triggers: `pull_request`, `push` to main/master, and `workflow_call` (reusable by CD).

```
test job (Python 3.11 + 3.12 matrix):
  1. Install from requirements-dev.txt
  2. python -m compileall -q raven attack tests
  3. python -m pytest -v
  4. python -m attack.idor (standalone module check)
  5. HTTP server smoke test (start server, hit all /api/demo/* endpoints)

docker job (needs: test):
  1. docker build -t raven:ci .
  2. docker run pytest inside container
  3. Container /api/health HTTP smoke test
```

### CD (`.github/workflows/cd.yml`)

Triggers: `push` to main/master, `v*` tags, manual dispatch.

```
ci job:
  └── Invokes full CI via workflow_call (reusable)

publish-container job (needs: ci):
  └── Build + push to ghcr.io with SHA-pinned tags
```

**Key design:** CD invokes the COMPLETE CI pipeline before publishing. Not a separate, weaker test suite.

### Actions Pinned to Commit SHAs

All third-party GitHub Actions are pinned to full commit SHAs for supply-chain security:
- `actions/checkout@11d5960...` (v4)
- `actions/setup-python@a26af69...` (v5)
- `docker/setup-buildx-action@8d2750c...` (v3)
- `docker/login-action@c94ce9f...` (v3)
- `docker/metadata-action@c299e40...` (v5)
- `docker/build-push-action@10e90e3...` (v6)

## V1 CI Quality Gates (Target)

The evaluation job should fail the pipeline if:
- FPR > 5%
- FNR > 10%
- Unsupported claim rate > 0%
- Hallucination rate > 0% (non-existent evidence IDs cited)
- Confidence label completeness < 100%

## Writing Tests — Guidelines

1. **Use `@pytest.mark.parametrize`** for boundary/edge case testing (see `test_security.py` for examples)
2. **Each VulnerableLabTarget variant** should have both a vulnerable and patched configuration
3. **Security tests must verify the ABSENCE of sensitive data** in stored evidence, not just the presence of redaction markers
4. **Integration tests should use `TestClient`** (FastAPI) once the migration is complete
5. **Never assert on AI output content** — assert on grounding status, confidence labels, and audit log entries instead
