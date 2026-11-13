# Skill: RAVEN System Architecture

## Current State (What Exists)

RAVEN currently runs as a **stdlib Python HTTP server** with an in-memory IDOR
demonstration. There is no database, no FastAPI, and no external dependencies
beyond `pytest` for testing.

### Existing Component Map

```
raven/
├── main.py                  # CLI entry point (argparse → run_server)
├── server/
│   ├── app.py               # ThreadingHTTPServer, CORS, static file serving, REST dispatch
│   └── routes.py            # DemoController (state manager for interactive demo)
├── core/
│   ├── models.py            # Observation, Evidence, Finding, AttackResult dataclasses
│   ├── policy.py            # Scope, PolicyDecision, PolicyGate (domain/path/budget/prereqs)
│   ├── store.py             # EvidenceStore (in-memory, sequential E01/E02 IDs)
│   └── validator.py         # FindingValidator.validate_idor() (deterministic)
├── ai/
│   ├── ollama.py            # OllamaClient (host auto-detect, generate())
│   └── tutor.py             # AITutor (progressive hints, explain_finding, remediation_diff)
└── target/
    ├── base.py              # BaseTarget, TargetRequest, TargetResponse abstractions
    ├── database.py          # LabDatabase (in-memory users + orders seed data)
    └── lab.py               # VulnerableLabTarget (FinBank API with is_vulnerable toggle)

attack/
├── base.py                  # AttackModule ABC (id, name, category, execute())
└── idor.py                  # IDORAttack (authenticate → baseline → tamper → validate)

web/                         # Vanilla HTML/CSS/JS dashboard (no build tools)
tests/                       # pytest: test_idor, test_policy, test_routes, test_security, test_target
```

## V1 Target Architecture (from docs/RAVEN_V1_Technical_Specification.md)

The V1 spec defines a layered architecture with these subsystems:

### API Layer
- **FastAPI** replaces stdlib `ThreadingHTTPServer`
- Routes: `/api/v1/assessments/*`, `/api/v1/learning/*`, `/api/demo/*` (preserved)
- All existing demo endpoints must continue to work unchanged

### Core Assessment Engine
- `AssessmentController` — lifecycle management (PENDING → RUNNING → COMPLETE)
- `PolicyGate` — scope, auth, budget, method allowlist (partially implemented)
- `AttackRegistry` — module dispatch
- `NetworkGateway` (**NEW**) — SSRF protection, DNS rebinding prevention, private IP blocking
- `RequestOrchestrator` — httpx-based with redirect scope re-validation
- `HumanOversightGate` (**NEW**) — approval workflow for active modules

### Evidence & Event Layer
- `RedactionPipeline` (**NEW**) — credential scrubbing before ANY storage; fail-closed
- `EvidenceStore` — SQLite-backed with HMAC-SHA256 chain (currently in-memory)
- `FindingValidator` — deterministic only; 5-state model (currently binary)
- `EventStream` — StepEvent persistence for student replay

### Trust Layer (6 components, all NEW)
- `AISafetyGuard` — prompt injection prevention
- `EvidenceGrounder` — citation verification for AI outputs
- `AIOutputVerifier` — prohibited pattern detection
- `ConfidenceAnnotator` — uncertainty labeling (MODERATE/LOW/AI_UNAVAILABLE)
- `PromptVersionManager` — model + template version tracking
- `AuditLogger` — ai_audit_log entry for every AI call

### AI Layer
- `AITutor` — Ollama client (partially implemented)
- `FallbackEngine` — deterministic explanation templates per finding type

### Persistence
- **SQLite WAL mode** — 9 tables (assessments, scopes, evidence, findings, assessment_events, ai_audit_log, scope_violations, oversight_decisions, prompt_versions, hmac_session_keys)

## Non-Negotiable Architectural Rules

1. **AI never determines finding status.** Only `FindingValidator` can transition finding states.
2. **Redaction happens before storage.** Secrets must never enter SQLite or any persistent store.
3. **PolicyGate and NetworkGateway are independent layers.** A bug in one must not remove the other's protection.
4. **The existing IDOR lab demo must always work.** All original `test_*.py` tests must pass after any change.
5. **Evidence IDs are stable and sequential** within an assessment session (E01, E02, ...).
6. **Every AI call must produce an `ai_audit_log` entry**, including fallbacks and failures.

## Implementation Stages (Roadmap)

| Stage | Focus | Duration | Key Deliverables |
|-------|-------|----------|------------------|
| 1 | Foundation + Core Trust | 2 weeks | FastAPI, SQLite, RedactionPipeline, HMAC chain, NetworkGateway |
| 2 | Passive Modules + Trust Layer | 2 weeks | Headers/Cookies/TLS modules, all 6 Trust Layer components |
| 3 | Active Modules + Human Oversight | 1–2 weeks | CORS, Sensitive Exposure, IDOR refactor, HumanOversightGate |
| 4 | Student Mode + Eval Harness | 2 weeks | StepEvent replay, evaluation metrics, AI reliability tests |
| 5 | Reports + Pro UI + CI/CD | 1 week | Report export, professional UI, CI quality gates |
