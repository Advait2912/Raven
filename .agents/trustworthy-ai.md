# Skill: Trustworthy AI — Safety, Grounding & Verification

## Core Principle

> AI reasons over evidence. It does not become the evidence.
> AI recommends actions. Deterministic controls decide whether those actions are permitted.
> AI never declares a vulnerability. Only FindingValidator can.

## Current State

- `AITutor` (`raven/ai/tutor.py`): 3-level progressive hints, `explain_finding()` with Ollama + deterministic fallback, `get_remediation_diff()`
- `OllamaClient` (`raven/ai/ollama.py`): Auto-detect host, `generate()`, `is_available()`, `get_available_models()`
- Deterministic fallback exists but is basic (hardcoded IDOR explanation)

## V1 Trust Layer Components (all NEW — Section 4 of spec)

### 1. RedactionPipeline
- **Position:** Before ANY storage operation and before AI context construction
- **Fail-closed:** If redaction raises an exception, the evidence write is ABORTED
- **Minimum patterns:** passwords, API keys, secrets, tokens, AWS keys, DB credentials, private keys
- **Placeholder format:** `[REDACTED:CREDENTIAL]`, `[REDACTED:TOKEN]`, `[REDACTED:KEY]`, etc.
- **Non-bypassable:** No config flag, env var, or feature toggle can disable redaction

### 2. AISafetyGuard (Prompt Injection Prevention)
- Target HTTP responses are included in AI prompts — a malicious server can embed model instructions
- Evidence must be passed as STRUCTURED DATA, never as freeform text
- System prompts are FIXED templates, never interpolated with user/target content
- Response bodies are summarized and length-limited (500 chars max), never passed verbatim

### 3. EvidenceGrounder (Citation Verification)
- Parse AI output for evidence ID references (E01, E02, etc.)
- Verify each cited ID exists in EvidenceStore for the current session
- Annotate: `FULLY_GROUNDED` | `PARTIALLY_GROUNDED` | `UNGROUNDED`
- Missing citations → `UNGROUNDED` → ConfidenceAnnotator receives `LOW_CONFIDENCE`

### 4. AIOutputVerifier (Prohibited Patterns)
Detect and reject AI outputs that:
- Declare vulnerabilities independently (`"I found a vulnerability"`, `"This confirms..."`)
- Assign severity levels (severity belongs to FindingValidator only)
- Contradict the deterministic validator's conclusion

```python
PROHIBITED_PATTERNS = [
    r'(?i)(confirms?|proves?|demonstrates?)\s+(a\s+)?(vulnerability|flaw|exploit)',
    r'(?i)I (found|detected|identified|confirmed)\s+(a\s+)?(security|vulnerability)',
    r'(?i)this is (definitely|certainly)\s+(a|an)\s+(vulnerability|exploit)',
    r'(?i)(CRITICAL|HIGH|MEDIUM|LOW)\s+severity\s+(vulnerability|finding|issue)',
]
```

If a prohibited pattern is detected → output is REJECTED → FallbackEngine triggered → audit entry created.

### 5. ConfidenceAnnotator (Uncertainty Labeling)

| Grounding | AI Available | Label | Display |
|-----------|-------------|-------|---------|
| FULLY_GROUNDED | Yes | `MODERATE_CONFIDENCE` | "Based on the recorded evidence, this suggests..." |
| PARTIALLY_GROUNDED | Yes | `LOW_CONFIDENCE` | "With partial evidence support, this may indicate..." |
| UNGROUNDED | Yes | `LOW_CONFIDENCE` + warning | "This explanation could not be verified against evidence." |
| Any | No | `AI_UNAVAILABLE` | "AI unavailable. Deterministic explanation shown." |

**Rule:** AI output is NEVER labeled `HIGH_CONFIDENCE`. High confidence is reserved for deterministic validator conclusions only.

### 6. PromptVersionManager
- Every prompt template has a version ID (e.g., `v1.idor.explanation`, `v1.headers.hint_1`)
- Every AI call records: `prompt_version` + `model_name` + `model_version`
- Store `SHA-256(prompt_input)` in `ai_audit_log` — not the full prompt if it contains evidence data

### 7. FallbackEngine (Deterministic Templates)
- **Trigger conditions:** Ollama down, timeout, AIOutputVerifier rejection, UNGROUNDED + strict policy, any unhandled AI pipeline exception
- **Contract:** Every finding type MUST have a fallback template BEFORE the module that produces it ships
- Fallback outputs reference evidence IDs without AI interpretation
- Always clearly labeled as `[Deterministic explanation — AI unavailable]`

## AI Call Pipeline (Order of Operations)

```
FindingValidator produces finding
        ↓
EvidenceGrounder: verify evidence exists for this session
        ↓
AISafetyGuard: sanitize evidence content for prompt
        ↓
PromptVersionManager: construct versioned prompt
        ↓
AITutor / OllamaClient: send to model
        ↓ (or timeout/error → FallbackEngine)
AIOutputVerifier: check for prohibited patterns
        ↓ (rejected → FallbackEngine)
ConfidenceAnnotator: attach confidence label
        ↓
AuditLogger: write ai_audit_log entry
        ↓
Return to presentation layer
```

## Non-Negotiable AI Rules

1. **AI never changes finding status.** It explains what FindingValidator already confirmed.
2. **Every AI call produces an `ai_audit_log` entry** — including failures and fallbacks.
3. **Confidence is always shown.** No AI explanation reaches the user without a confidence label.
4. **Fallback is always available.** If AI fails for any reason, a deterministic template takes over.
5. **No raw response bodies in prompts.** Evidence is summarized, length-limited, and sanitized.
