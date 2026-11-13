# Skill: Web Dashboard & Frontend

## Current State

The frontend is a **zero-build vanilla HTML/CSS/JS** single-page application in `web/`:

```
web/
├── index.html              # Dashboard shell with 4 panels
├── css/
│   ├── variables.css       # CSS custom properties (colors, fonts, spacing)
│   ├── layout.css          # App container and dashboard grid
│   ├── panels.css          # Panel card styling
│   ├── topology.css        # Network topology visualization and animations
│   ├── inspector.css       # Burp-style HTTP traffic viewer
│   └── evidence.css        # Evidence cards and finding alerts
└── js/
    ├── api.js              # RavenAPI fetch wrapper for /api/demo/* endpoints
    ├── components.js       # UI rendering functions (traffic, evidence, findings, topology, diffs)
    └── app.js              # Event wiring, step/patch state management
```

### 4 Dashboard Panels

1. **Target Topology & Execution Stepper** — Visualizes Attacker (Alice) → Policy Gate → FinBank Lab API → Target Database with animated packet flow and compromise highlighting
2. **HTTP Traffic Inspector (Burp View)** — Tabbed raw request/response viewer for each step (Auth, Baseline 101, Tamper 102)
3. **Evidence Store & Deterministic Findings** — Evidence cards with ID, type, status coloring; finding alert cards with vulnerability/secure status
4. **AI Tutor & Remediation Hub** — Tabbed: Progressive Hints (3 levels), AI Reasoning (with model tag + grounding badge), Code Patch (vulnerable vs. secure side-by-side diff)

### Header Controls

- **Run Attack** — Executes full 3-step IDOR scenario
- **Next Step** — Advances phase-by-phase (1→2→3)
- **Patch Target** / **Unpatch Target** — Toggles `is_vulnerable` on the lab target
- **Reset** — Clears all state

## V1 Frontend Requirements

### Student Mode (Section 10 of spec)

- **Non-dismissible replay banner** on every view indicating assessment is a replay, not live
- **StepEvent-driven navigation** (Next/Back) through all 6 module step sequences
- **Topology highlight** follows current step with animated packet flow
- **Confidence labels visible** on every AI explanation (MODERATE_CONFIDENCE, LOW_CONFIDENCE, AI_UNAVAILABLE)
- **Progressive hints** per module (3 levels: guide → compare → solution)

### Professional Mode (Section 10 of spec)

- Full finding cards with expandable evidence chains
- Clear visual separation of AI-generated vs. deterministic content
- Audit trail visibility (ai_audit_log references)
- Assessment lifecycle controls (start, approve, stop)

### API Endpoints the Frontend Calls

**Current (demo lab):**
- `POST /api/demo/run` — Run full IDOR attack
- `POST /api/demo/step` — Run single step `{"step": 1|2|3}`
- `POST /api/demo/patch` — Toggle vulnerability `{"is_vulnerable": bool}`
- `POST /api/demo/reset` — Reset state
- `GET /api/demo/evidence` — Get evidence items
- `GET /api/demo/hints?level=N` — Get progressive hint
- `GET /api/demo/explain` — Get AI explanation
- `GET /api/demo/remediation` — Get code diff
- `GET /api/demo/models` — List Ollama models
- `POST /api/demo/model` — Switch model

**V1 Assessment API (new):**
- `POST /api/v1/assessments` — Create assessment
- `GET /api/v1/assessments/{id}` — Status
- `POST /api/v1/assessments/{id}/run` — Start
- `POST /api/v1/assessments/{id}/approve/{step}` — Human approval
- `POST /api/v1/assessments/{id}/stop` — Stop
- `GET /api/v1/assessments/{id}/findings` — Findings
- `GET /api/v1/assessments/{id}/evidence` — Evidence
- `GET /api/v1/assessments/{id}/events` — SSE event stream
- `GET /api/v1/assessments/{id}/report` — Download report

**V1 Learning API (new):**
- `GET /api/v1/learning/{id}/steps` — Step count
- `GET /api/v1/learning/{id}/step/{n}` — Step event at sequence n
- `GET /api/v1/learning/{id}/explain/{finding_id}` — AI explanation with confidence
- `GET /api/v1/learning/{id}/hint?level=N` — Progressive hint
- `GET /api/v1/learning/{id}/remediation/{finding_id}` — Code patch

## Non-Negotiable Frontend Rules

1. **Existing demo endpoints must continue to work unchanged.** The demo lab is preserved as-is.
2. **Student mode replay banner is non-dismissible.** Users must always know they're viewing a replay.
3. **Confidence labels must appear on every AI explanation.** No AI text is shown without its confidence annotation.
4. **AI-generated content must be visually distinct** from deterministic validator output.
5. **No build tools required.** The frontend uses vanilla HTML/CSS/JS. No npm, webpack, or React.
