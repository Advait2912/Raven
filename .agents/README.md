# RAVEN — Agent Skills & Development Knowledge

This directory contains structured knowledge files ("skills") that AI coding agents,
contributors, and developers can reference when working on RAVEN.

Each file covers a specific domain of the project and captures:
- What exists today and where to find it in the codebase
- What the V1 specification requires
- Architectural constraints and non-negotiable rules
- Testing expectations

## Skill Index

| Skill | Domain | When to Read |
|-------|--------|--------------|
| `architecture.md` | System architecture, component map, and layering rules | Before touching any core component or adding a new module |
| `attack-modules.md` | Writing and extending attack/assessment modules | Before implementing or modifying any module in `attack/` |
| `trustworthy-ai.md` | AI safety, grounding, verification, and the Trust Layer | Before touching anything in `raven/ai/` or adding AI features |
| `evidence-and-data.md` | Evidence models, data governance, redaction, and persistence | Before modifying evidence storage, models, or database schema |
| `policy-and-security.md` | PolicyGate, NetworkGateway, scope enforcement, and SSRF defense | Before modifying scope checks, network requests, or security boundaries |
| `testing.md` | Test strategy, CI/CD pipeline, and quality gates | Before writing tests or modifying GitHub Actions workflows |
| `frontend.md` | Web dashboard, Student Mode, Professional Mode | Before modifying anything in `web/` or adding UI features |

## How to Use

- **AI Agents:** Read the relevant skill file(s) before starting work on a task.
- **Contributors:** Skim the skill for the area you're contributing to; pay attention to "Non-Negotiable Rules" sections.
- **Reviewers:** Reference these skills when reviewing PRs to check architectural compliance.
