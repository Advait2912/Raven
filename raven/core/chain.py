# Cryptographic HMAC-SHA256 Evidence Chain for RAVEN.
# Design choice: Provide tamper-evident ordering verification for all stored evidence.
# An unbroken chain proves evidence has not been modified, injected, or removed.

import hashlib
import hmac
import json
import secrets
from typing import Any, Optional, Tuple
from .models import Evidence


class EvidenceChain:
    """Tamper-evident HMAC-SHA256 evidence chain."""

    GENESIS_HASH = "0" * 64

    def __init__(self, session_key: Optional[bytes] = None) -> None:
        self.session_key = session_key or secrets.token_bytes(32)
        self.key_hash = hashlib.sha256(self.session_key).hexdigest()
        self.current_hash = self.GENESIS_HASH

    @staticmethod
    def canonical_json(data: Any) -> str:
        """Produce deterministic, sorted JSON representation."""
        return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)

    @classmethod
    def compute_evidence_digest(cls, evidence: Evidence) -> str:
        """Calculate SHA-256 digest of an evidence item's canonical content."""
        canonical_content = {
            "id": evidence.id,
            "evidence_type": evidence.evidence_type,
            "request_method": evidence.request_method,
            "request_path": evidence.request_path,
            "request_headers": evidence.request_headers,
            "request_body": evidence.request_body,
            "response_status": evidence.response_status,
            "response_headers": evidence.response_headers,
            "response_body": evidence.response_body,
            "authenticated_actor": evidence.authenticated_actor,
            "resource_owner": evidence.resource_owner,
            "observation": evidence.observation,
            "assessment_id": evidence.assessment_id,
            "recorded_at": evidence.recorded_at or evidence.timestamp,
        }
        canonical_str = cls.canonical_json(canonical_content)
        return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

    def sign_evidence(self, evidence: Evidence) -> str:
        """Compute the next chain hash for an evidence item and advance the chain."""
        content_digest = self.compute_evidence_digest(evidence)
        payload = f"{self.current_hash}:{content_digest}".encode("utf-8")
        next_hash = hmac.new(self.session_key, payload, hashlib.sha256).hexdigest()
        self.current_hash = next_hash
        evidence.chain_hash = next_hash
        return next_hash

    @classmethod
    def verify_chain(
        cls,
        evidence_list: list[Evidence],
        session_key: bytes,
        genesis_hash: str = GENESIS_HASH,
    ) -> Tuple[bool, Optional[str]]:
        """Verify an evidence sequence against the session key.

        Returns (True, None) if the chain is intact.
        Returns (False, error_reason) if any evidence was tampered with,
        deleted, reordered, or forged.
        """
        running_hash = genesis_hash

        for idx, ev in enumerate(evidence_list):
            if not ev.chain_hash:
                return False, f"Evidence item {ev.id} (index {idx}) is missing chain_hash."

            content_digest = cls.compute_evidence_digest(ev)
            payload = f"{running_hash}:{content_digest}".encode("utf-8")
            expected_hash = hmac.new(session_key, payload, hashlib.sha256).hexdigest()

            if not hmac.compare_digest(expected_hash, ev.chain_hash):
                return False, (
                    f"Integrity check failed at evidence {ev.id} (index {idx}): "
                    f"expected chain hash {expected_hash}, found {ev.chain_hash}."
                )

            running_hash = expected_hash

        return True, None
