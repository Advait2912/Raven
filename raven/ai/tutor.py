# AI Tutor & Security Analyst.
# Follows Section 8 of arch.md: Grounded in empirical evidence, explains root causes,
# provides progressive hints, and offers deterministic remediation patches.

from typing import Any, Optional
from raven.core.models import Evidence, Finding
from .ollama import OllamaClient


class AITutor:
    """Tutor and analyst providing grounded explanations and progressive learning hints."""

    def __init__(self, ollama_client: Optional[OllamaClient] = None) -> None:
        self.ollama = ollama_client or OllamaClient()

    def get_progressive_hint(self, level: int) -> dict[str, str]:
        """Return progressive hints without immediately spoiling solutions."""
        hints = {
            1: {
                "title": "Hint 1: Parameter Analysis",
                "content": "Look closely at the request URI `/api/orders/{id}`. The `{id}` path parameter is a direct reference to a database object identifier. Does the application restrict which IDs an authenticated user can request?",
            },
            2: {
                "title": "Hint 2: Cross-User Ownership",
                "content": "Compare Evidence E01 and E02. In E01, Alice retrieves order 101 (owned by `usr_alice`). In E02, Alice changes the parameter to 102 and receives Bob's data (owned by `usr_bob`) with HTTP 200 OK!",
            },
            3: {
                "title": "Solution & Root Cause",
                "content": "Broken Object-Level Authorization (IDOR). The backend retrieves the order record solely based on the user-supplied identifier without validating whether `order.owner_id == session.user_id`.",
            },
        }
        return hints.get(level, hints[1])

    def explain_finding(
        self,
        finding: Finding,
        evidence_list: list[Evidence],
        use_llm: bool = True,
    ) -> dict[str, Any]:
        """Explain the confirmed finding, citing exact evidence IDs."""
        ev_summary = "\n".join(
            f"- [{ev.id}] {ev.request_method} {ev.request_path} -> HTTP {ev.response_status} (Actor: {ev.authenticated_actor}, Owner: {ev.resource_owner})"
            for ev in evidence_list
        )

        llm_response = None
        if use_llm and self.ollama.is_available():
            prompt = (
                f"You are the RAVEN AI Security Tutor. Explain this finding based strictly on the evidence below.\n"
                f"Finding: {finding.vulnerability_type} on {finding.endpoint}\n"
                f"Evidence:\n{ev_summary}\n\n"
                f"Provide: 1) What happened citing evidence IDs, 2) Impact, 3) How to fix."
            )
            llm_response = self.ollama.generate(
                prompt=prompt,
                system_prompt="You are a trustworthy AI cybersecurity instructor. Ground all explanations in cited Evidence IDs.",
            )

        explanation = llm_response or (
            f"IDOR (Insecure Direct Object Reference) confirmed on endpoint `{finding.endpoint}`.\n\n"
            f"**Evidence Grounding:**\n"
            f"- **E01**: Alice legitimately retrieved order `101` with status HTTP 200.\n"
            f"- **E02**: Alice tampered with the object identifier to request order `102` and successfully accessed Bob's confidential order without authorization.\n\n"
            f"**Impact:**\n{finding.impact}\n\n"
            f"**Root Cause:**\n{finding.root_cause}"
        )

        return {
            "finding_id": finding.id,
            "vulnerability": finding.vulnerability_type,
            "severity": finding.severity,
            "evidence_cited": finding.evidence_ids,
            "explanation": explanation,
            "model_used": self.ollama.model if llm_response else "deterministic-rules-engine",
        }

    def get_remediation_diff(self) -> dict[str, str]:
        """Return a clean diff showing vulnerable code vs secure remediated code."""
        vulnerable_code = (
            "@app.get('/api/orders/{order_id}')\n"
            "def get_order(order_id: str, user: User = Depends(get_current_user)):\n"
            "    order = db.find_order(order_id)\n"
            "    if not order:\n"
            "        raise HTTPException(status_code=404, detail='Order not found')\n"
            "    # VULNERABILITY: Missing authorization check!\n"
            "    return order"
        )
        secure_code = (
            "@app.get('/api/orders/{order_id}')\n"
            "def get_order(order_id: str, user: User = Depends(get_current_user)):\n"
            "    order = db.find_order(order_id)\n"
            "    if not order:\n"
            "        raise HTTPException(status_code=404, detail='Order not found')\n"
            "    # REMEDIATION: Enforce object-level access control\n"
            "    if order.owner_id != user.id and not user.is_admin:\n"
            "        raise HTTPException(status_code=403, detail='Forbidden')\n"
            "    return order"
        )
        return {
            "vulnerable": vulnerable_code,
            "secure": secure_code,
            "language": "python",
            "explanation": "Add an explicit authorization check comparing `order.owner_id` with `user.id`. Return HTTP 403 Forbidden on mismatch.",
        }
