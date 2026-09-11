# Deterministic finding validator.
# Design choice: empirical confirmation over AI speculation.
# A vulnerability is only confirmed when cross-user resource access is proven.

from typing import Optional
from .models import Evidence, Finding


class FindingValidator:
    """Deterministic validator that confirms or rejects candidate findings."""

    @staticmethod
    def validate_idor(
        evidence_list: list[Evidence],
    ) -> Optional[Finding]:
        """Validate IDOR by checking if any evidence proves cross-user leakage."""
        confirming_evidence: list[str] = []

        for ev in evidence_list:
            # Condition 1: Must be HTTP 200 OK
            if ev.response_status != 200:
                continue

            # Condition 2: Must involve authenticated actor and distinct resource owner
            if ev.authenticated_actor and ev.resource_owner:
                if ev.authenticated_actor != ev.resource_owner:
                    confirming_evidence.append(ev.id)

        if not confirming_evidence:
            return None

        return Finding(
            id="FINDING-IDOR-01",
            vulnerability_type="Insecure Direct Object Reference (IDOR)",
            severity="HIGH",
            endpoint="/api/orders/{id}",
            evidence_ids=confirming_evidence,
            confirmed=True,
            impact="Authenticated users can read sensitive order and personal data belonging to other accounts.",
            root_cause="Missing object-level access control check: the server queries by order_id without verifying owner_id == current_user.id.",
            remediation="Enforce ownership validation in the endpoint handler: verify `order.owner_id == authenticated_user.id` or return 403 Forbidden.",
        )
