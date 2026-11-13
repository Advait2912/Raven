# Skill: PolicyGate, NetworkGateway & Security Boundaries

## Current State

### PolicyGate (`raven/core/policy.py`) — Partially Implemented

What's done:
- `Scope` dataclass: `allowed_domains`, `allowed_paths`, `max_requests`, `current_requests`
- `PolicyGate.evaluate()`: domain allowlist check, path prefix matching with normalization, request budget, prerequisite verification
- Path traversal defense (`..`, backslash, null byte rejection, `posixpath.normpath`)
- 30 passing tests including parametrized security boundary tests (`tests/test_security.py`)

What's missing:
- Method allowlist (only GET/POST are used today; no `allowed_methods` field yet)
- SQLite-backed scope persistence (currently in-memory dataclass)
- `scope_violations` logging table

### NetworkGateway — Not Started

This is a **critical missing component** for V1.

## V1 Dual-Layer Scope Enforcement

The spec mandates TWO independent enforcement layers:

```
Request lifecycle:

  PolicyGate.evaluate(url)
    └── Domain allowlist, path prefix, method permitted, budget remaining
    └── Violation → record in scope_violations table, block, return DENY
    ↓

  NetworkGateway.validate(url)
    └── Resolve DNS → check resolved IP against private range blocklist
    └── Violation → record in scope_violations table, block
    ↓

  RequestOrchestrator.execute(request)
    └── Fires httpx request
    ↓

  For EACH redirect:
    └── NetworkGateway.validate(redirect_target)   ← re-validate resolved IP
    └── PolicyGate.evaluate(redirect_target)       ← re-check domain/path
```

**Key design principle:** These two layers are independently testable. A bug in PolicyGate does not remove NetworkGateway protection, and vice versa.

## NetworkGateway Specification

### Private IP Blocklist (Required)

Block requests to ALL of these ranges:
- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`
- `127.0.0.0/8`
- `169.254.0.0/16` (link-local, including AWS metadata at `169.254.169.254`)
- `::1` (IPv6 loopback)
- `fc00::/7` (IPv6 private)
- `0.0.0.0/8`

### DNS Rebinding Prevention

A target hostname may resolve to a public IP during scope validation but resolve to
a private IP when the actual request fires. The NetworkGateway must:

1. Resolve DNS **once per request** (not cache from scope-entry time)
2. Check the resolved IP against the private range blocklist **at request time**
3. If the IP is private → block, log to `scope_violations`, raise `NetworkGatewayError`

### Redirect Safety

For every HTTP redirect:
1. Extract redirect target URL
2. Resolve DNS for the new hostname
3. Check resolved IP against private range blocklist (NetworkGateway)
4. Check domain and path against scope allowlist (PolicyGate)
5. If either check fails → block the redirect, log violation
6. Maximum redirect depth: configurable (default 5)

## Threat Model (from Section 13 of spec)

| ID | Threat | Control | Component |
|----|--------|---------|-----------|
| T01 | SSRF via HTTP redirect to internal IP | Private IP blocking, DNS re-validation per request | NetworkGateway |
| T02 | DNS rebinding to bypass scope | DNS resolved per request; IP re-checked at request time | NetworkGateway |
| T06 | Unauthorized assessment triggering | V1: localhost-only binding; V1.1: API auth | Deployment config |
| T09 | Scope expansion via crafted redirect | PolicyGate + NetworkGateway re-validate on each redirect | Both layers |

## scope_violations Table

```sql
CREATE TABLE scope_violations (
    id               TEXT PRIMARY KEY,
    assessment_id    TEXT REFERENCES assessments(id),
    violation_type   TEXT NOT NULL,     -- DOMAIN_OUT_OF_SCOPE | PRIVATE_IP | BUDGET_EXCEEDED | DNS_REBINDING | PATH_NOT_ALLOWED
    attempted_target TEXT NOT NULL,
    blocked_by       TEXT NOT NULL,     -- PolicyGate | NetworkGateway
    timestamp        TEXT NOT NULL
);
```

Every PolicyGate or NetworkGateway block must create a `scope_violations` entry.

## Non-Negotiable Security Rules

1. **NetworkGateway blocks private IPs.** No code path bypasses this for real targets.
2. **DNS is resolved per request.** Never cached from scope-entry time.
3. **Every redirect leg is re-validated** by both PolicyGate and NetworkGateway.
4. **All violations are logged** to `scope_violations` with the blocked target and blocking component.
5. **V1 API binds to `127.0.0.1` only.** Binding to `0.0.0.0` without authentication is a HIGH risk.
6. **PolicyGate and NetworkGateway are independent.** Test each in isolation. Never combine them into a single component.
