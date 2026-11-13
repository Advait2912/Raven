# Evidence store for RAVEN with redaction, HMAC chaining, and SQLite persistence.
# Design choice: stable sequential IDs (E01, E02...) to enable clear citation,
# with cryptographic tamper-evidence and automatic secret scrubbing.

import threading
from typing import Optional, Tuple
from .chain import EvidenceChain
from .db import Database
from .models import Evidence, Finding, Observation, ScopeViolation
from .redaction import RedactionPipeline


class EvidenceStore:
    """Thread-safe store for recorded evidence, findings, and observations."""

    def __init__(
        self,
        db_path: Optional[str] = None,
        session_key: Optional[bytes] = None,
        assessment_id: str = "default",
    ) -> None:
        self.assessment_id = assessment_id
        self._lock = threading.Lock()
        self._evidence: list[Evidence] = []
        self._observations: list[Observation] = []
        self._findings: list[Finding] = []
        self._scope_violations: list[ScopeViolation] = []
        self._counter: int = 0

        # Cryptographic chain
        self.chain = EvidenceChain(session_key=session_key)

        # Optional SQLite persistence
        self.db: Optional[Database] = Database(db_path) if db_path else None
        if self.db:
            self.db.save_hmac_key_hash(
                assessment_id=self.assessment_id,
                key_hash=self.chain.key_hash,
                created_at=self.chain.GENESIS_HASH,
            )

    @property
    def session_key(self) -> bytes:
        return self.chain.session_key

    def next_id(self) -> str:
        """Generate a stable sequential ID like E01, E02, etc."""
        with self._lock:
            self._counter += 1
            return f"E{self._counter:02d}"

    def add_evidence(self, evidence: Evidence) -> Evidence:
        """Redact, sign with HMAC chain, and persist an Evidence item.

        Guaranteed fail-closed: If redaction fails, the item is NOT stored.
        """
        # Step 1: Redaction before storage (fail-closed)
        redacted_ev = RedactionPipeline.redact_evidence(evidence)
        redacted_ev.assessment_id = self.assessment_id

        with self._lock:
            # Step 2: Cryptographic HMAC chain link
            self.chain.sign_evidence(redacted_ev)

            # Step 3: In-memory append
            self._evidence.append(redacted_ev)

            # Step 4: Optional SQLite persistence
            if self.db:
                self.db.save_evidence(redacted_ev)

        return redacted_ev

    def add_observation(self, observation: Observation) -> None:
        with self._lock:
            self._observations.append(observation)

    def add_finding(self, finding: Finding) -> None:
        finding.assessment_id = self.assessment_id
        with self._lock:
            self._findings.append(finding)
            if self.db:
                self.db.save_finding(finding)

    def add_scope_violation(self, violation: ScopeViolation) -> None:
        violation.assessment_id = self.assessment_id
        with self._lock:
            self._scope_violations.append(violation)
            if self.db:
                self.db.save_scope_violation(violation)

    def get_evidence(self, evidence_id: str) -> Optional[Evidence]:
        with self._lock:
            for item in self._evidence:
                if item.id == evidence_id:
                    return item
            return None

    def get_all_evidence(self) -> list[Evidence]:
        with self._lock:
            return list(self._evidence)

    def get_all_observations(self) -> list[Observation]:
        with self._lock:
            return list(self._observations)

    def get_all_findings(self) -> list[Finding]:
        with self._lock:
            return list(self._findings)

    def get_all_scope_violations(self) -> list[ScopeViolation]:
        with self._lock:
            return list(self._scope_violations)

    def verify_integrity(self) -> Tuple[bool, Optional[str]]:
        """Verify the cryptographic integrity of all stored evidence items.

        Returns (True, None) if the chain is valid.
        Returns (False, reason) if any record was modified, reordered, or deleted.
        """
        with self._lock:
            return EvidenceChain.verify_chain(
                evidence_list=self._evidence,
                session_key=self.chain.session_key,
            )

    def clear(self) -> None:
        with self._lock:
            self._evidence.clear()
            self._observations.clear()
            self._findings.clear()
            self._scope_violations.clear()
            self._counter = 0
            self.chain = EvidenceChain()
