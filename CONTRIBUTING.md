# Contributing to RAVEN

Thank you for your interest in contributing to **RAVEN** (Reasoning-based Autonomous Vulnerability Exploration Network).

This guide covers everything you need to get started: setting up your environment, running the project, writing tests, and submitting a pull request.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
- [Running Locally](#running-locally)
- [Running Tests](#running-tests)
- [Docker Development](#docker-development)
- [Pull Request Workflow](#pull-request-workflow)
- [Code Style & Architecture](#code-style--architecture)
- [Writing Attack Modules](#writing-attack-modules)
- [Security Testing Expectations](#security-testing-expectations)
- [Skill Files](#skill-files)

---

## Prerequisites

- **Python 3.11+** (3.11 and 3.12 are tested in CI)
- **Git**
- **Docker** (optional, for container testing)
- **Ollama** (optional, for AI tutor features — not required for core assessment engine)

## Getting Started

1. **Fork** the repository on GitHub.

2. **Clone** your fork:
   ```bash
   git clone https://github.com/<your-username>/Raven.git
   cd Raven
   ```

3. **Create a virtual environment:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate   # Linux / macOS
   .venv\Scripts\activate      # Windows
   ```

4. **Install dependencies:**
   ```bash
   pip install -r requirements-dev.txt
   ```

   `requirements-dev.txt` includes test dependencies (`pytest`) and pulls in `requirements.txt` (runtime deps) automatically.

## Running Locally

Start the RAVEN server:
```bash
python -m raven.main
```

The server starts on `http://localhost:8000` by default. You can specify a different port:
```bash
python -m raven.main --port 9000
```

Key endpoints:
| Endpoint | Description |
|----------|-------------|
| `/` | Web dashboard |
| `/api/health` | Health check |
| `/api/scan` | Start an IDOR assessment |
| `/api/scan/status` | Assessment status |
| `/api/scope` | View/update scope configuration |

## Running Tests

Set `PYTHONPATH` so imports resolve correctly, then run pytest:

```bash
# Linux / macOS
PYTHONPATH=. python -m pytest -v

# Windows (PowerShell)
$env:PYTHONPATH = "."
python -m pytest -v
```

### Test categories

| File | What it covers |
|------|---------------|
| `tests/test_idor.py` | IDOR module unit tests |
| `tests/test_api.py` | REST API integration tests (starts a live server) |
| `tests/test_security.py` | PolicyGate enforcement, scope boundaries, fail-closed behavior |

All tests must pass before a PR can be merged. CI runs the full suite on both Python 3.11 and 3.12.

### Running a single test file

```bash
PYTHONPATH=. python -m pytest tests/test_security.py -v
```

## Docker Development

### Build the image

```bash
docker build -t raven:dev .
```

### Run tests inside the container

```bash
docker run --rm raven:dev python -m pytest -v
```

### Start the server in a container

```bash
docker run -p 8000:8000 raven:dev
```

The container includes a `HEALTHCHECK` that polls `/api/health` every 30 seconds.

## Pull Request Workflow

1. **Create a feature branch** from `master`:
   ```bash
   git checkout -b feature/my-change
   ```

2. **Make your changes.** Follow the architecture guidelines in [`.agents/`](.agents/README.md).

3. **Write or update tests.** Every behavioral change needs a test. Security-related changes need a test in `tests/test_security.py`.

4. **Run the full test suite locally** and make sure everything passes:
   ```bash
   PYTHONPATH=. python -m pytest -v
   ```

5. **Commit** with a descriptive message:
   ```bash
   git commit -m "feat: add CORS misconfiguration module"
   ```

   We use [Conventional Commits](https://www.conventionalcommits.org/) style prefixes:
   - `feat:` — new feature
   - `fix:` — bug fix
   - `docs:` — documentation only
   - `test:` — adding or updating tests
   - `ci:` — CI/CD changes
   - `refactor:` — code restructuring with no behavior change

6. **Push** your branch and **open a Pull Request** against `master`.

7. **Wait for CI.** GitHub Actions runs automatically on every PR:
   - Python 3.11 + 3.12 matrix tests
   - Syntax compilation check (`compileall`)
   - IDOR module standalone execution
   - API smoke tests against a live server
   - Docker build + container tests

8. **Request a review.** At least one approval is required before merging. Code Owners review is also required.

> [!IMPORTANT]
> The `master` branch is protected. Direct pushes are not allowed. All changes must go through a pull request with passing CI and an approved review.

## Code Style & Architecture

- **No external runtime dependencies unless approved.** RAVEN currently runs on the Python standard library only. If you need a new dependency, discuss it in the PR.
- **PolicyGate is non-negotiable.** Every outbound HTTP request must pass through PolicyGate scope checks. Never bypass or weaken scope enforcement.
- **Fail closed.** If a security check cannot determine whether an action is safe, it must deny the action.
- **No credentials in evidence.** All stored evidence must go through the RedactionPipeline (once implemented). Never store raw API keys, tokens, or passwords.
- **Layer boundaries matter.** Modules in `attack/` must not import from `raven/server/`. The server layer calls down to the core layer, never the reverse.

For detailed architecture rules, read [`.agents/architecture.md`](.agents/architecture.md).

## Writing Attack Modules

Every assessment module must follow the standard interface:

```python
class MyModule:
    """Module docstring with OWASP/CWE references."""

    def __init__(self, config: dict):
        self.config = config

    def run(self, target: str, scope: Scope) -> list[Finding]:
        # 1. Validate target against scope (PolicyGate)
        # 2. Perform assessment (passive or active)
        # 3. Return typed Findings with evidence
        ...
```

Key rules:
- Every finding must include evidence (request/response pairs, timestamps, reproduction steps).
- Confidence levels must be justified — never inflate severity.
- Modules must respect the request budget in `Scope`.
- All network requests must be scope-checked before execution.

For the complete module specification, read [`.agents/attack-modules.md`](.agents/attack-modules.md).

## Security Testing Expectations

RAVEN is a cybersecurity platform. Security-related contributions have higher testing requirements:

| Scenario | Required test |
|----------|--------------|
| New attack module | Unit test + integration test with live server |
| Scope enforcement change | Test in `test_security.py` for allow AND deny cases |
| New outbound HTTP path | SSRF protection test (once NetworkGateway exists) |
| Evidence storage change | Redaction and integrity tests |
| PolicyGate modification | Full regression of `test_security.py` |

> [!CAUTION]
> CI must never make requests to external hosts. All tests use `localhost` test servers or mock objects. If your test needs a vulnerable target, create a local fixture.

## Skill Files

The [`.agents/`](.agents/) directory contains structured knowledge files that cover every major subsystem. **Read the relevant skill before working on that area:**

| Skill | Read before touching... |
|-------|------------------------|
| [`architecture.md`](.agents/architecture.md) | Any core component or new module |
| [`attack-modules.md`](.agents/attack-modules.md) | Anything in `attack/` |
| [`trustworthy-ai.md`](.agents/trustworthy-ai.md) | Anything in `raven/ai/` |
| [`evidence-and-data.md`](.agents/evidence-and-data.md) | Evidence storage, models, or database schema |
| [`policy-and-security.md`](.agents/policy-and-security.md) | Scope checks, network requests, security boundaries |
| [`testing.md`](.agents/testing.md) | Tests or CI/CD workflows |
| [`frontend.md`](.agents/frontend.md) | Anything in `web/` |

---

## Questions?

Open an issue on GitHub if something is unclear. We'd rather answer a question than review a PR that went in the wrong direction.
