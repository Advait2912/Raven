# SQLite persistence layer for RAVEN.
# Design choice: Zero external dependencies (stdlib sqlite3).
# Uses WAL mode and foreign keys for durability and concurrent reads.

import json
import sqlite3
from typing import Any, Optional
from .models import Evidence, Finding, FindingStatus, ScopeViolation


SCHEMA_SQL = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS assessments (
    id TEXT PRIMARY KEY,
    target_url TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    completed_at TEXT
);

CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL,
    evidence_type TEXT NOT NULL,
    request_method TEXT NOT NULL,
    request_path TEXT NOT NULL,
    request_headers TEXT NOT NULL,
    request_body TEXT,
    response_status INTEGER NOT NULL,
    response_headers TEXT NOT NULL,
    response_body TEXT,
    authenticated_actor TEXT,
    resource_owner TEXT,
    observation TEXT NOT NULL,
    chain_hash TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL,
    vulnerability_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    evidence_ids TEXT NOT NULL,
    confirmed INTEGER NOT NULL,
    confidence REAL NOT NULL,
    impact TEXT,
    root_cause TEXT,
    remediation TEXT,
    cwe_id TEXT,
    cvss_score REAL
);

CREATE TABLE IF NOT EXISTS scope_violations (
    id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL,
    violation_type TEXT NOT NULL,
    attempted_target TEXT NOT NULL,
    blocked_by TEXT NOT NULL,
    details TEXT,
    timestamp TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hmac_session_keys (
    assessment_id TEXT PRIMARY KEY,
    key_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


class Database:
    """Manages SQLite storage for assessment sessions, evidence, and audit logs."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.executescript(SCHEMA_SQL)

    def save_evidence(self, ev: Evidence) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO evidence (
                    id, assessment_id, evidence_type, request_method, request_path,
                    request_headers, request_body, response_status, response_headers,
                    response_body, authenticated_actor, resource_owner, observation,
                    chain_hash, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ev.id,
                    ev.assessment_id,
                    ev.evidence_type,
                    ev.request_method,
                    ev.request_path,
                    json.dumps(ev.request_headers),
                    json.dumps(ev.request_body) if ev.request_body is not None else None,
                    ev.response_status,
                    json.dumps(ev.response_headers),
                    json.dumps(ev.response_body) if ev.response_body is not None else None,
                    ev.authenticated_actor,
                    ev.resource_owner,
                    ev.observation,
                    ev.chain_hash or "",
                    ev.recorded_at or ev.timestamp,
                ),
            )

    def save_finding(self, f: Finding) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO findings (
                    id, assessment_id, vulnerability_type, severity, status,
                    endpoint, evidence_ids, confirmed, confidence, impact,
                    root_cause, remediation, cwe_id, cvss_score
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f.id,
                    f.assessment_id,
                    f.vulnerability_type,
                    f.severity,
                    f.status.value if isinstance(f.status, FindingStatus) else str(f.status),
                    f.endpoint,
                    json.dumps(f.evidence_ids),
                    1 if f.confirmed else 0,
                    f.confidence,
                    f.impact,
                    f.root_cause,
                    f.remediation,
                    f.cwe_id,
                    f.cvss_score,
                ),
            )

    def save_scope_violation(self, sv: ScopeViolation) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO scope_violations (
                    id, assessment_id, violation_type, attempted_target,
                    blocked_by, details, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sv.id,
                    sv.assessment_id,
                    sv.violation_type,
                    sv.attempted_target,
                    sv.blocked_by,
                    sv.details,
                    sv.timestamp,
                ),
            )

    def save_hmac_key_hash(self, assessment_id: str, key_hash: str, created_at: str) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO hmac_session_keys (assessment_id, key_hash, created_at)
                VALUES (?, ?, ?)
                """,
                (assessment_id, key_hash, created_at),
            )

    def get_evidence(self, assessment_id: Optional[str] = None) -> list[Evidence]:
        query = "SELECT * FROM evidence"
        params: list[Any] = []
        if assessment_id:
            query += " WHERE assessment_id = ? ORDER BY id ASC"
            params.append(assessment_id)
        else:
            query += " ORDER BY id ASC"

        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()

        results = []
        for r in rows:
            results.append(
                Evidence(
                    id=r["id"],
                    assessment_id=r["assessment_id"],
                    evidence_type=r["evidence_type"],
                    request_method=r["request_method"],
                    request_path=r["request_path"],
                    request_headers=json.loads(r["request_headers"]),
                    request_body=json.loads(r["request_body"]) if r["request_body"] else None,
                    response_status=r["response_status"],
                    response_headers=json.loads(r["response_headers"]) if r["response_headers"] else {},
                    response_body=json.loads(r["response_body"]) if r["response_body"] else None,
                    authenticated_actor=r["authenticated_actor"],
                    resource_owner=r["resource_owner"],
                    observation=r["observation"],
                    chain_hash=r["chain_hash"],
                    timestamp=r["recorded_at"],
                    recorded_at=r["recorded_at"],
                )
            )
        return results

    def get_findings(self, assessment_id: Optional[str] = None) -> list[Finding]:
        query = "SELECT * FROM findings"
        params: list[Any] = []
        if assessment_id:
            query += " WHERE assessment_id = ? ORDER BY id ASC"
            params.append(assessment_id)
        else:
            query += " ORDER BY id ASC"

        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()

        results = []
        for r in rows:
            results.append(
                Finding(
                    id=r["id"],
                    assessment_id=r["assessment_id"],
                    vulnerability_type=r["vulnerability_type"],
                    severity=r["severity"],
                    status=FindingStatus(r["status"]) if r["status"] in FindingStatus._value2member_map_ else FindingStatus.CONFIRMED,
                    endpoint=r["endpoint"],
                    evidence_ids=json.loads(r["evidence_ids"]),
                    confirmed=bool(r["confirmed"]),
                    confidence=float(r["confidence"]),
                    impact=r["impact"] or "",
                    root_cause=r["root_cause"] or "",
                    remediation=r["remediation"] or "",
                    cwe_id=r["cwe_id"],
                    cvss_score=r["cvss_score"],
                )
            )
        return results

    def get_scope_violations(self, assessment_id: Optional[str] = None) -> list[ScopeViolation]:
        query = "SELECT * FROM scope_violations"
        params: list[Any] = []
        if assessment_id:
            query += " WHERE assessment_id = ? ORDER BY timestamp ASC"
            params.append(assessment_id)
        else:
            query += " ORDER BY timestamp ASC"

        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()

        return [
            ScopeViolation(
                id=r["id"],
                assessment_id=r["assessment_id"],
                violation_type=r["violation_type"],
                attempted_target=r["attempted_target"],
                blocked_by=r["blocked_by"],
                details=r["details"] or "",
                timestamp=r["timestamp"],
            )
            for r in rows
        ]
