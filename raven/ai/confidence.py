"""Confidence Annotator for RAVEN Trustworthy AI.

Calibrates AI confidence scores mathematically:
- Grounding score based on verified citations vs claims
- Severity alignment: bounds confidence if evidence is baseline-only rather than differential
- Discards and replaces arbitrary LLM self-reported confidence
"""

from dataclasses import dataclass, field
from typing import Any, List, Optional, Union
from raven.core.models import Evidence, Finding, FindingStatus


@dataclass
class ConfidenceResult:
    """Outcome of mathematical confidence calibration."""
    confidence: float
    grounding_score: float
    evidence_completeness: float
    is_bounded: bool
    bounding_reason: Optional[str] = None
    raw_llm_confidence: Optional[float] = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "confidence": self.confidence,
            "grounding_score": self.grounding_score,
            "evidence_completeness": self.evidence_completeness,
            "is_bounded": self.is_bounded,
            "bounding_reason": self.bounding_reason,
            "raw_llm_confidence": self.raw_llm_confidence,
            "details": self.details,
        }


class ConfidenceAnnotator:
    """Mathematical calibrator for AI assessment confidence."""

    MAX_BASELINE_CONFIDENCE = 0.35  # Cap when evidence only shows legitimate baseline

    def __init__(self, max_baseline_confidence: float = MAX_BASELINE_CONFIDENCE) -> None:
        self.max_baseline_confidence = max_baseline_confidence

    def calculate_grounding_score(
        self,
        verified_citations_count: int,
        total_claims_count: int,
    ) -> float:
        """Calculate grounding ratio: Verified Citations / Total Claims."""
        if total_claims_count <= 0:
            return 1.0 if verified_citations_count > 0 else 0.0

        if verified_citations_count == 0:
            return 0.0

        ratio = verified_citations_count / float(total_claims_count)
        return round(min(1.0, max(0.0, ratio)), 4)

    def evaluate_differential_access(
        self,
        evidence_list: list[Evidence],
    ) -> tuple[bool, float, str]:
        """Evaluate whether evidence contains differential unauthorized access or is baseline-only.
        
        Returns:
            (has_differential_access, completeness_score, description)
        """
        if not evidence_list:
            return False, 0.0, "No evidence provided."

        has_baseline = False
        has_differential_tamper = False

        for ev in evidence_list:
            ev_type = (ev.evidence_type or "").upper()
            status = ev.response_status

            if "BASELINE" in ev_type:
                has_baseline = True
            elif "TAMPER" in ev_type or "UNAUTHORIZED" in ev_type:
                # Differential access: unauthorized status 200 with mismatched owner
                actor = ev.authenticated_actor
                owner = ev.resource_owner
                if status == 200 and actor and owner and actor != owner:
                    has_differential_tamper = True
                elif status == 200:
                    has_differential_tamper = True

        if has_differential_tamper and has_baseline:
            return True, 1.0, "Full differential unauthorized access verified with baseline contrast."
        elif has_differential_tamper:
            return True, 0.8, "Differential unauthorized access verified (lacks baseline contrast)."
        elif has_baseline:
            return False, 0.4, "Evidence consists solely of baseline HTTP access."
        else:
            return False, 0.2, "Evidence inconclusive without differential authorization telemetry."

    def calibrate(
        self,
        verified_citations: list[str],
        total_claims: int,
        evidence_list: list[Evidence],
        finding: Optional[Finding] = None,
        raw_llm_confidence: Optional[float] = None,
    ) -> ConfidenceResult:
        """Calibrate confidence mathematically, bounding if baseline-only.
        
        Replaces arbitrary LLM self-reported confidence.
        """
        unique_verified = len(set(verified_citations))
        grounding_score = self.calculate_grounding_score(unique_verified, total_claims)

        has_differential, completeness, diff_reason = self.evaluate_differential_access(evidence_list)

        # Base score weighted 70% grounding, 30% evidence completeness
        base_score = (0.7 * grounding_score) + (0.3 * completeness)

        # If zero verified citations, confidence is strictly zero
        if unique_verified == 0:
            return ConfidenceResult(
                confidence=0.0,
                grounding_score=0.0,
                evidence_completeness=completeness,
                is_bounded=False,
                bounding_reason="Zero verified evidence citations in AI explanation.",
                raw_llm_confidence=raw_llm_confidence,
                details={
                    "formula": "Zero verified citations => 0.0",
                    "differential_evidence": diff_reason,
                },
            )

        # Severity alignment: Bound confidence if baseline only
        is_bounded = False
        bounding_reason = None

        if not has_differential:
            is_bounded = True
            bounding_reason = (
                f"Confidence bounded to {self.max_baseline_confidence} because evidence "
                f"lacks differential unauthorized access ({diff_reason})."
            )
            calibrated = min(self.max_baseline_confidence, base_score)
        else:
            # If finding is provided and marked unconfirmed/invalidated, bound as well
            if finding and finding.status in (FindingStatus.UNCONFIRMED, FindingStatus.INVALIDATED):
                is_bounded = True
                bounding_reason = f"Confidence bounded because finding status is {finding.status.value}."
                calibrated = min(self.max_baseline_confidence, base_score)
            else:
                calibrated = min(1.0, max(0.0, base_score))

        calibrated = round(calibrated, 2)

        return ConfidenceResult(
            confidence=calibrated,
            grounding_score=round(grounding_score, 2),
            evidence_completeness=round(completeness, 2),
            is_bounded=is_bounded,
            bounding_reason=bounding_reason,
            raw_llm_confidence=raw_llm_confidence,
            details={
                "base_score": round(base_score, 2),
                "unique_verified_citations": unique_verified,
                "total_claims": total_claims,
                "differential_access": has_differential,
                "differential_reason": diff_reason,
            },
        )
