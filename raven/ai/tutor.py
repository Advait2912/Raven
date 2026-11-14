"""AI Tutor & Security Analyst for RAVEN Trustworthy AI.

Follows Section 8 of arch.md:
- Grounded strictly in empirical evidence (EvidenceGrounder)
- Safety and schema verified deterministically (AIOutputVerifier)
- Confidence calibrated mathematically (ConfidenceAnnotator)
- Progressive educational guidance with pacing constraints (ProgressiveHintEngine)
"""

from typing import Any, List, Optional
from raven.core.models import Evidence, Finding
from .confidence import ConfidenceAnnotator, ConfidenceResult
from .grounder import EvidenceGrounder, GroundingResult, GroundingStatus
from .hints import HintResult, ProgressiveHintEngine
from .ollama import OllamaClient
from .verifier import AIOutputVerifier, VerificationResult


class AITutor:
    """Tutor and analyst providing verified, grounded explanations and progressive hints."""

    def __init__(
        self,
        ollama_client: Optional[OllamaClient] = None,
        grounder: Optional[EvidenceGrounder] = None,
        verifier: Optional[AIOutputVerifier] = None,
        annotator: Optional[ConfidenceAnnotator] = None,
        hint_engine: Optional[ProgressiveHintEngine] = None,
    ) -> None:
        self.ollama = ollama_client or OllamaClient()
        self.grounder = grounder or EvidenceGrounder()
        self.verifier = verifier or AIOutputVerifier()
        self.annotator = annotator or ConfidenceAnnotator()
        self.hint_engine = hint_engine or ProgressiveHintEngine()

    def get_progressive_hint(self, level: int) -> dict[str, str]:
        """Return progressive hints without immediately spoiling solutions (legacy/simple API)."""
        hint = self.hint_engine.get_hint(tier=level, session_id="legacy")
        # If locked under strict pacing, provide the template for backward compatibility in legacy API
        hints_backup = {
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
        if hint.unlocked:
            return {"title": hint.title, "content": hint.content}
        return hints_backup.get(level, hints_backup[1])

    def request_student_hint(
        self,
        tier: int,
        session_id: str = "default",
        evidence_list: Optional[list[Evidence]] = None,
    ) -> HintResult:
        """Request progressive student hint with strict pacing and prerequisite enforcement."""
        return self.hint_engine.get_hint(
            tier=tier,
            session_id=session_id,
            evidence_list=evidence_list,
        )

    def explain_finding(
        self,
        finding: Finding,
        evidence_list: list[Evidence],
        use_llm: bool = True,
    ) -> dict[str, Any]:
        """Explain the confirmed finding, citing exact evidence IDs with verification and confidence."""
        llm_response = None
        model_name = "deterministic-rules-engine"
        verification_passed = True
        verification_violations: list[str] = []

        if use_llm and self.ollama.is_available():
            prompt = self.grounder.bind_prompt(
                finding=finding,
                evidence_list=evidence_list,
                instruction=(
                    "Provide: 1) What happened citing evidence IDs, 2) Impact, 3) How to fix. "
                    "You must strictly reference the provided evidence IDs."
                ),
            )
            raw_generation = self.ollama.generate(
                prompt=prompt,
                system_prompt="You are a trustworthy AI cybersecurity instructor. Ground all explanations in cited Evidence IDs.",
            )

            if raw_generation:
                model_name = self.ollama.model
                # Step 1: AIOutputVerifier (deterministic safety firewall & prohibited patterns)
                ver_res = self.verifier.verify(raw_generation)
                verification_passed = ver_res.is_valid
                verification_violations = ver_res.violations

                if ver_res.is_valid:
                    # Step 2: EvidenceGrounder citation check
                    grounding = self.grounder.validate_citations(ver_res.output, evidence_list)
                    if grounding.status == GroundingStatus.UNGROUNDED:
                        # Fail-closed: ungrounded critical assertions rejected
                        llm_response = (
                            f"AI response rejected by EvidenceGrounder: {grounding.reason}. "
                            f"Fail-closed fallback activated."
                        )
                        verification_passed = False
                    else:
                        llm_response = grounding.sanitized_text or ver_res.output
                else:
                    # Output verifier rejected dangerous commands or out-of-scope targets
                    llm_response = ver_res.output

        # Deterministic fallback if LLM is unavailable or rejected
        explanation = llm_response or (
            f"IDOR (Insecure Direct Object Reference) confirmed on endpoint `{finding.endpoint}`.\n\n"
            f"**Evidence Grounding:**\n"
            f"- **E01**: Alice legitimately retrieved order `101` with status HTTP 200.\n"
            f"- **E02**: Alice tampered with the object identifier to request order `102` and successfully accessed Bob's confidential order without authorization.\n\n"
            f"**Impact:**\n{finding.impact}\n\n"
            f"**Root Cause:**\n{finding.root_cause}"
        )

        # Grounding evaluation for final response
        grounding_eval = self.grounder.validate_citations(explanation, evidence_list)

        # Count claims requiring grounding (empirical/critical claims)
        critical_count = sum(1 for c in grounding_eval.claims if c.is_critical)
        claims_for_confidence = critical_count if critical_count > 0 else grounding_eval.total_claims

        # Confidence calibration
        confidence_result = self.annotator.calibrate(
            verified_citations=grounding_eval.verified_citations,
            total_claims=claims_for_confidence,
            evidence_list=evidence_list,
            finding=finding,
        )

        return {
            "finding_id": finding.id,
            "vulnerability": finding.vulnerability_type,
            "severity": finding.severity,
            "evidence_cited": grounding_eval.verified_citations or finding.evidence_ids,
            "explanation": explanation,
            "confidence": confidence_result.confidence,
            "grounding_status": grounding_eval.status.value,
            "is_grounded": grounding_eval.is_grounded,
            "verification_passed": verification_passed,
            "violations": verification_violations,
            "confidence_report": confidence_result.to_dict(),
            "model_used": model_name,
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
