# RAVEN — Reasoning-based Autonomous Vulnerability Exploration Network

RAVEN is an AI-assisted cybersecurity learning and vulnerability assessment platform built around a core Trustworthy AI design principle:

> **Observe → Structure Evidence → Reason → Constrain → Execute → Validate → Explain**

Rather than giving an LLM unrestricted execution or treating model output as ground truth, RAVEN separates **probabilistic AI reasoning** (tutoring, explanations, hints) from **deterministic system controls** (policy gates, attack execution, structured evidence capture, and finding validation).

---

## Current Implementation Status

The repository currently implements a complete **end-to-end vertical slice** (Mode B — **Learning Application Lab**) centered on **Insecure Direct Object Reference (IDOR)**:

| Subsystem | Status | Description |
| :--- | :--- | :--- |
| **Core Data Models & Evidence Store** | Implemented | Typed `Observation`, `Evidence`, `Finding`, and `AttackResult` models with sequential evidence IDs (`E01`, `E02`, …). |
| **Deterministic Policy Gate** | Implemented | Code-level `PolicyGate` enforcing `Scope` (allowed domains, allowed path prefixes, request budget) and prerequisite checks. |
| **Deterministic Finding Validator** | Implemented | `FindingValidator.validate_idor()` confirms IDOR only when HTTP `200` returns a resource whose `resource_owner` differs from `authenticated_actor`. |
| **Attack Engine (`IDORAttack`)** | Implemented | Modular `AttackModule` interface and `IDORAttack` testing baseline vs. tampered order access. |
| **Vulnerable Lab Target** | Implemented | In-memory **FinBank Order Management API** (`VulnerableLabTarget`) with toggleable vulnerability/patch state (`is_vulnerable`). |
| **AI Tutor & Ollama Client** | Implemented | Local/host `OllamaClient` with auto-discovery, 3-level progressive hints, evidence-grounded explanations (with deterministic fallback), and code patch diffing. |
| **REST Server & Web Dashboard** | Implemented | Zero-dependency Python stdlib `ThreadingHTTPServer` + dark-mode Burp-inspired dashboard (`web/`). |
| **Containerization** | Implemented | `Dockerfile` (`python:3.12-slim`, non-root user, healthcheck) and `docker-compose.yml` wired to host Ollama. |
| **Automated Tests** | Implemented | `pytest` unit and integration tests covering target behavior, IDOR detection/patching, policy gate, and `DemoController` flows. |

---

## Architecture Overview

```text
Web Dashboard (web/)
       │  REST API (/api/demo/*)
       ▼
RavenRequestHandler & DemoController (raven/server/)
       │
       ├──► PolicyGate (raven/core/policy.py)
       │        └─ Enforces Scope (domains, paths, budget) & prerequisites
       │
       ├──► IDORAttack (attack/idor.py) ──► VulnerableLabTarget (raven/target/lab.py)
       │        │                                └─ In-memory LabDatabase (Users & Orders)
       │        ▼
       │    EvidenceStore (raven/core/store.py)
       │        └─ Sequential Evidence (E01, E02) & Observations
       │        │
       │        ▼
       │    FindingValidator (raven/core/validator.py)
       │        └─ Deterministic cross-user ownership check
       │
       └──► AITutor (raven/ai/tutor.py) ──► OllamaClient (raven/ai/ollama.py)
                └─ Progressive hints, evidence-grounded explanation, remediation diff
```

---

## Repository Structure

```text
Raven/
├── .github/
│   └── workflows/
│       ├── ci.yml           # PR & push CI (Python 3.11/3.12 pytest, smoke test, Docker test)
│       └── cd.yml           # CD container build & publish to GHCR on push/tags
├── attack/
│   ├── base.py              # AttackModule abstract base class
│   └── idor.py              # IDORAttack module (also runnable via python -m attack.idor)
├── docs/
│   └── arch.md              # Full platform architecture, research thesis, & evaluation design
├── raven/
│   ├── ai/
│   │   ├── ollama.py        # Ollama HTTP client with Docker/WSL/localhost host detection
│   │   └── tutor.py         # AITutor: progressive hints, finding explanation, remediation diff
│   ├── core/
│   │   ├── models.py        # Observation, Evidence, Finding, AttackResult dataclasses
│   │   ├── policy.py        # Scope and PolicyGate deterministic enforcement
│   │   ├── store.py         # EvidenceStore with sequential ID generation (E01, E02...)
│   │   └── validator.py     # FindingValidator (deterministic IDOR verification)
│   ├── server/
│   │   ├── app.py           # Stdlib ThreadingHTTPServer, CORS, static hosting, REST dispatch
│   │   └── routes.py        # DemoController managing full/stepped runs & patch state
│   ├── target/
│   │   ├── base.py          # BaseTarget, TargetRequest, TargetResponse abstractions
│   │   ├── database.py      # LabDatabase seeding users (alice, bob) and orders (101, 102)
│   │   └── lab.py           # VulnerableLabTarget (FinBank Order Management API)
│   └── main.py              # CLI entry point (--host, --port)
├── tests/
│   ├── test_idor.py         # IDOR detection on vulnerable vs. patched target
│   ├── test_policy.py       # PolicyGate allow, domain scope, and prerequisite checks
│   ├── test_routes.py       # DemoController full and step-by-step execution tests
│   ├── test_security.py     # Security boundary, traversal, budget & false-positive tests
│   └── test_target.py       # VulnerableLabTarget health, auth, leak, and 403 patch tests
├── web/
│   ├── css/                 # Modular stylesheets (variables, layout, panels, topology, inspector, evidence)
│   ├── js/
│   │   ├── api.js           # Fetch wrapper (RavenAPI) for /api/demo/* endpoints
│   │   ├── components.js    # UI renderers for HTTP traffic, evidence, findings, topology, diffs
│   │   └── app.js           # Dashboard event wiring & step/patch state management
│   └── index.html           # Single-page interactive RAVEN dashboard
├── Dockerfile               # Python 3.12-slim container (non-root `raven` user, /api/health check)
├── docker-compose.yml       # Service definition with host.docker.internal Ollama wiring
├── requirements.txt         # Production runtime dependencies (stdlib-only today)
└── requirements-dev.txt     # Development & CI test dependencies (pytest)
```

---

## Implemented Components in Detail

### 1. Core Trust & Evidence Layer (`raven/core/`)
- **Models (`models.py`)**:
  - `Observation`: Records step name, action, details, and UTC timestamp.
  - `Evidence`: Captures stable ID (`E01`, `E02`, …), `evidence_type`, HTTP request method/path/headers/body, response status/body, `authenticated_actor`, `resource_owner`, and human-readable `observation`.
  - `Finding`: Represents a confirmed vulnerability (`id`, `vulnerability_type`, `severity`, `endpoint`, `evidence_ids`, `confirmed`, `impact`, `root_cause`, `remediation`).
  - `AttackResult`: Bundles `success`, `status` (`VULNERABILITY_CONFIRMED`, `VULNERABILITY_NOT_DETECTED`, or `PREREQUISITE_FAILED`), collected evidence, findings, and telemetry.
- **Policy Gate (`policy.py`)**:
  - Default `Scope` restricts targets to `["localhost", "127.0.0.1", "lab.local"]`, permitted path prefixes `["/api/auth/login", "/api/orders/"]`, and a `50`-request budget.
  - `PolicyGate.evaluate()` verifies domain, path prefix, remaining budget, and prerequisites before returning `PolicyDecision`.
- **Validator (`validator.py`)**:
  - `FindingValidator.validate_idor()` inspects `Evidence` items and produces `FINDING-IDOR-01` (`HIGH`) only when at least one item has `response_status == 200` and `authenticated_actor != resource_owner`.

### 2. Attack Engine & Vulnerable Lab (`attack/`, `raven/target/`)
- **Seed Data (`LabDatabase`)**:
  - Users: `alice` (`usr_alice`, token `tok_alice_session_8819`) and `bob` (`usr_bob`, token `tok_bob_session_9921`).
  - Orders: Order `101` (`owner_id="usr_alice"`, *Quantum Mechanical Keyboard*, `$149.99`) and Order `102` (`owner_id="usr_bob"`, *Confidential Security Hardened Router*, `$899.50`).
- **Lab Endpoints (`VulnerableLabTarget`)**:
  - `GET /api/health` — returns target status and `vulnerable` flag.
  - `POST /api/auth/login` — validates credentials and returns Bearer token.
  - `GET /api/orders/{id}` — authenticates Bearer token; when `is_vulnerable=True`, returns any existing order regardless of owner (`200 OK`). When `is_vulnerable=False` (patched), checks `order.owner_id != user.id` and returns `403 Forbidden`.
- **Attack Flow (`IDORAttack`)**:
  1. **Authenticate** as `alice` via `POST /api/auth/login`.
  2. **Baseline Probe**: `GET /api/orders/101` (Alice's own order) → Evidence `E01` (`HTTP_BASELINE_ACCESS`).
  3. **Parameter Tamper**: `GET /api/orders/102` (Bob's order) → Evidence `E02` (`HTTP_TAMPER_ACCESS`).
  4. **Validate**: Runs `FindingValidator.validate_idor()` to confirm or reject IDOR.

### 3. AI Tutor & Ollama Integration (`raven/ai/`)
- **`OllamaClient` (`ollama.py`)**:
  - Auto-detects reachable Ollama instances (`OLLAMA_HOST`, `host.docker.internal`, `192.168.192.1`, `127.0.0.1`, `localhost` on port `11434`).
  - Default model is `qwen3.5:9b` (overridable via `OLLAMA_MODEL` env var or `POST /api/demo/model`; `docker-compose.yml` configures `gemma4:31b-cloud`).
- **`AITutor` (`tutor.py`)**:
  - **Progressive Hints**: 3 levels (`1`: Parameter Analysis, `2`: Cross-User Ownership, `3`: Solution & Root Cause).
  - **Grounded Explanation**: Prompts Ollama with exact `Evidence` IDs and metadata; if Ollama is offline or unavailable, falls back seamlessly to a deterministic rules-engine explanation citing `E01` and `E02`.
  - **Remediation Diff**: Supplies vulnerable vs. secure Python handler code enforcing `order.owner_id != user.id`.

### 4. Web Dashboard & API (`raven/server/`, `web/`)
The frontend (`web/index.html`) uses vanilla HTML/CSS/JS with zero build steps and provides four main panels:
1. **Target Topology & Execution Stepper**: Visualizes `Attacker (Alice)` → `Policy Gate` → `FinBank Lab API` → `Target Database`, highlighting active flow and compromise state.
2. **HTTP Traffic Inspector (Burp View)**: Raw HTTP request/response viewer tabbed by step (`1: Auth`, `2: Baseline (101)`, `3: Tamper (102)`).
3. **Evidence Store & Deterministic Findings**: Lists recorded `E01`/`E02` cards and displays either `[VULNERABILITY DETECTED]` or `[TARGET SECURE]` status alerts.
4. **AI Tutor & Remediation Hub**: Tabs for **Progressive Hints**, **AI Reasoning**, and side-by-side **Code Patch** comparison.

Header controls allow running the full scenario (`Run Attack`), advancing phase-by-phase (`Next Step`), toggling the backend authorization fix (`Patch Target` / `Unpatch Target`), and resetting state (`Reset`).

---

## API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Service health check (`status`, `service`, `version`). |
| `GET` | `/api/demo/models` | Lists current and available Ollama models. |
| `GET` | `/api/demo/evidence` | Returns all recorded `Evidence` items in `EvidenceStore`. |
| `GET` | `/api/demo/hints?level=1` | Returns progressive hint (`level` `1`, `2`, or `3`). |
| `GET` | `/api/demo/explain` | Returns AI Tutor (or deterministic fallback) explanation for confirmed findings. |
| `GET` | `/api/demo/remediation` | Returns vulnerable vs. secure Python code diff. |
| `POST` | `/api/demo/run` | Runs `PolicyGate` check + full `IDORAttack` execution (preserving current patch state). |
| `POST` | `/api/demo/step` | Runs a single guided step (`{"step": 1 \| 2 \| 3}`). |
| `POST` | `/api/demo/patch` | Toggles target vulnerability (`{"is_vulnerable": true \| false}`). |
| `POST` | `/api/demo/model` | Switches active Ollama model (`{"model": "<name>"}`). |
| `POST` | `/api/demo/reset` | Resets target database, evidence store, policy gate, and step state. |

---

## Getting Started

### Run Locally (Python 3.12+)
The runtime server and attack engine use **Python standard library only** (no external packages required to launch the server; `pytest` is used for tests):

```bash
# Start the dashboard and API server on http://localhost:8000
python -m raven.main --host 0.0.0.0 --port 8000
```

To execute the standalone IDOR module check in the terminal:

```bash
python -m attack.idor
```

Optional environment variables for local LLM integration:
- `OLLAMA_HOST` — Ollama base URL (e.g., `http://127.0.0.1:11434`).
- `OLLAMA_MODEL` — Model name (defaults to `qwen3.5:9b`).

### Run with Docker Compose

```bash
docker compose up --build
```

This builds the `raven-platform` container on port `8000` and configures `OLLAMA_HOST=http://host.docker.internal:11434` with `OLLAMA_MODEL=gemma4:31b-cloud`.

### Run Tests

```bash
pytest -v
```

Test coverage across `tests/`:
- `tests/test_idor.py` — Full IDOR confirmation and patched target verification.
- `tests/test_policy.py` — Scope allow, out-of-scope domain rejection, and missing prerequisite rejection.
- `tests/test_target.py` — Lab health, login authentication, order `102` leak, and `403 Forbidden` patch enforcement.
- `tests/test_routes.py` — `DemoController` full vulnerable run, full patched run, and 3-step patched run.
- `tests/test_security.py` — Security boundary tests (out-of-scope domains, path traversal & prefix spoofing, request budget limits, false-positive prevention, unauthenticated/unsupported HTTP methods, and fail-closed `DemoController`).

### CI/CD (GitHub Actions)
- **CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml))**: Runs on pull requests, pushes to `main`/`master`, and via `workflow_call`:
  - Installs `requirements-dev.txt`, runs syntax checks (`compileall`), runs `pytest` across Python `3.11` and `3.12`, runs standalone `attack.idor`, and runs a live HTTP server + REST API smoke test.
  - Builds the Docker image, runs `pytest` inside the container, and verifies `/api/health` on the running container.
- **CD ([`.github/workflows/cd.yml`](.github/workflows/cd.yml))**: On pushes to `main`/`master`, `v*` release tags, or manual dispatch, invokes the full reusable CI workflow (`workflow_call`) before publishing SHA-pinned container images to GitHub Container Registry (`ghcr.io`) with least-privilege `packages: write` scoped strictly to the publish job.

---

## Development History (Git Milestones)

1. **`chore(infra)`** — Configured `.gitignore`, `Dockerfile`, and `docker-compose.yml` containerization.
2. **`feat(core)`** — Implemented `PolicyGate`/`Scope`, `EvidenceStore`, `FindingValidator`, `VulnerableLabTarget` (FinBank mock target), `OllamaClient`/`AITutor`, and the HTTP server/controller.
3. **`feat(attack)`** — Added `AttackModule` base class and `IDORAttack` module with multi-step telemetry.
4. **`feat(web)`** — Built the dark-mode dashboard, live topology stepper, Burp-style traffic inspector, and remediation hub.
5. **`test`** — Added unit and integration tests for IDOR validation, policy gating, lab target behavior, and patch toggling.

---

## Roadmap (Planned in `docs/arch.md`)

The full architecture specification in `docs/arch.md` outlines upcoming phases beyond the current IDOR vertical slice:
- **Additional Attack Modules**: SQL Injection, XSS, Authentication flaws, API authorization, and SSRF.
- **Mode A (Attack Simulation) & Mode C (Authorized Live Pentesting)**: Expanding beyond the in-memory lab to simulated scenarios and explicitly scoped live targets.
- **AI Pentest Agent & Analyst Roles**: Constrained next-attack selection from an explicit action catalog with abstention states (`NEEDS_RECON`, `INSUFFICIENT_EVIDENCE`, `STOP`) and auditable decision logs.
- **Trustworthiness Evaluation Harness**: Benchmark suite and error taxonomy comparing unconstrained LLMs against evidence-grounded, policy-gated, and deterministically validated configurations.

