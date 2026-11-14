"""Evidence Grounder for RAVEN Trustworthy AI.

Binds model prompts strictly to verified evidence IDs from EvidenceStore,
extracts citations, detects hallucinations, and flags/strips ungrounded claims.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, List, Optional, Set, Union
from raven.core.models import Evidence, Finding
from raven.core.store import EvidenceStore


class GroundingStatus(str, Enum):
    """Grounding state of AI generation."""
    GROUNDED = "GROUNDED"
    PARTIALLY_GROUNDED = "PARTIALLY_GROUNDED"
    UNGROUNDED = "UNGROUNDED"


@dataclass
class ClaimAssertion:
    """A single factual claim extracted from model output."""
    text: str
    citations: list[str]
    is_grounded: bool
    is_critical: bool
    hallucinated_citations: list[str] = field(default_factory=list)


@dataclass
class GroundingResult:
    """Evaluation result from EvidenceGrounder."""
    status: GroundingStatus
    is_grounded: bool
    citations: list[str]
    verified_citations: list[str]
    hallucinated_citations: list[str]
    total_claims: int
    grounded_claims: int
    ungrounded_claims: int
    claims: list[ClaimAssertion] = field(default_factory=list)
    sanitized_text: str = ""
    reason: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "is_grounded": self.is_grounded,
            "citations": self.citations,
            "verified_citations": self.verified_citations,
            "hallucinated_citations": self.hallucinated_citations,
            "total_claims": self.total_claims,
            "grounded_claims": self.grounded_claims,
            "ungrounded_claims": self.ungrounded_claims,
            "sanitized_text": self.sanitized_text,
            "reason": self.reason,
        }


class EvidenceGrounder:
    """Binds prompts to verified evidence and verifies citations in AI outputs."""

    # Matches bracketed citations like [E01], [E02]
    BRACKETED_CITATION_PATTERN = re.compile(r"\[(E\d+)\]", re.IGNORECASE)
    # Matches word citations like E01, E02 (preceded by Evidence, request, etc. or standalone)
    WORD_CITATION_PATTERN = re.compile(r"\b(E\d+)\b", re.IGNORECASE)

    # Keywords that indicate a critical security assertion requiring evidence grounding
    CRITICAL_KEYWORDS = {
        "access", "unauthorized", "idor", "vulnerability", "order", "status",
        "http", "token", "actor", "owner", "bob", "alice", "returned", "200",
        "403", "forbidden", "tamper", "confidential", "flaw", "bypass", "exploit",
        "leak", "exposure", "credential", "session", "insecure", "privilege"
    }

    # Prefixes / keywords indicating remediation, mitigation, or conceptual advice
    REMEDIATION_INDICATORS = {
        "remediation", "to fix", "fix:", "solution", "mitigation", "patch",
        "recommendation", "recommended", "prevent", "should verify", "requires verifying"
    }

    def __init__(self, store: Optional[EvidenceStore] = None) -> None:
        self.store = store

    def extract_citations(self, text: str) -> list[str]:
        """Extract all evidence citation identifiers from text, normalized uppercase."""
        if not text:
            return []
        
        # Primary: bracketed citations e.g. [E01]
        bracketed = self.BRACKETED_CITATION_PATTERN.findall(text)
        # Secondary: word citations e.g. Evidence E01
        words = self.WORD_CITATION_PATTERN.findall(text)

        # Preserve order while deduplicating
        citations: list[str] = []
        for cid in bracketed + words:
            normalized = cid.upper()
            if normalized not in citations:
                citations.append(normalized)
        return citations

    def extract_claims(self, text: str) -> list[str]:
        """Extract individual claims/statements from text."""
        if not text:
            return []

        claims: list[str] = []
        # Split by lines first to preserve bullet points / list items
        lines = [line.strip() for line in text.split("\n") if line.strip()]
        for line in lines:
            # If line is a markdown list item or bullet
            if line.startswith(("-", "*", ">")) or re.match(r"^\d+[\.\)]", line):
                clean_line = re.sub(r"^[-*>\d\.\)\s]+", "", line).strip()
                if clean_line:
                    claims.append(clean_line)
            else:
                # Split sentences
                sentences = re.split(r"(?<=[.!?])\s+", line)
                for s in sentences:
                    s_clean = s.strip()
                    if s_clean and len(s_clean) > 5:
                        claims.append(s_clean)

        return claims

    def is_critical_claim(self, claim: str) -> bool:
        """Determine if a statement makes a critical empirical/telemetry assertion.
        
        Remediation advice, mitigation steps, and conceptual guidance do not assert
        unverified attack observations and are not treated as ungrounded empirical claims.
        """
        claim_lower = claim.lower().strip()

        # Check for remediation or general prescriptive advice
        if any(claim_lower.startswith(p) for p in ("remediation", "to fix", "fix:", "solution", "mitigation", "patch", "recommendation")):
            return False

        if any(ind in claim_lower for ind in self.REMEDIATION_INDICATORS):
            # Only critical if it also explicitly makes an empirical observation claim (e.g. status 200, returned)
            if not any(k in claim_lower for k in ("returned", "retrieved", "received", "status 200", "tampered")):
                return False

        words = set(re.findall(r"\b\w+\b", claim_lower))
        return len(words.intersection(self.CRITICAL_KEYWORDS)) >= 1

    def resolve_valid_ids(
        self,
        evidence_source: Optional[Union[EvidenceStore, list[Evidence], set[str], list[str]]] = None
    ) -> set[str]:
        """Resolve valid evidence IDs from active store or explicit source."""
        source = evidence_source if evidence_source is not None else self.store
        if source is None:
            return set()

        if isinstance(source, EvidenceStore):
            return {e.id.upper() for e in source.get_all_evidence()}
        elif isinstance(source, list) and source and isinstance(source[0], Evidence):
            return {e.id.upper() for e in source}
        elif isinstance(source, (set, list)):
            return {str(item).upper() for item in source}
        return set()

    def validate_citations(
        self,
        text: str,
        evidence_source: Optional[Union[EvidenceStore, list[Evidence], set[str], list[str]]] = None
    ) -> GroundingResult:
        """Cross-reference all citations in text against valid evidence.
        
        Flags hallucinated citations and ungrounded critical claims.
        """
        valid_ids = self.resolve_valid_ids(evidence_source)
        all_citations = self.extract_citations(text)
        verified_citations = [c for c in all_citations if c in valid_ids]
        hallucinated_citations = [c for c in all_citations if c not in valid_ids]

        claims_raw = self.extract_claims(text)
        analyzed_claims: list[ClaimAssertion] = []
        grounded_count = 0
        ungrounded_count = 0

        for claim in claims_raw:
            claim_citations = self.extract_citations(claim)
            claim_verified = [c for c in claim_citations if c in valid_ids]
            claim_hallucinated = [c for c in claim_citations if c not in valid_ids]
            is_critical = self.is_critical_claim(claim)

            # Claim grounding logic:
            # - If it has hallucinated citations -> ungrounded
            # - If it's a critical claim and has 0 verified citations -> ungrounded
            # - If it has verified citations -> grounded
            # - If non-critical with no citations -> neutral/grounded
            if claim_hallucinated:
                is_grounded = False
            elif is_critical:
                is_grounded = len(claim_verified) > 0
            else:
                is_grounded = True

            if is_grounded:
                grounded_count += 1
            else:
                ungrounded_count += 1

            analyzed_claims.append(ClaimAssertion(
                text=claim,
                citations=claim_citations,
                is_grounded=is_grounded,
                is_critical=is_critical,
                hallucinated_citations=claim_hallucinated,
            ))

        # Determine overall grounding status
        if not claims_raw:
            status = GroundingStatus.GROUNDED if not hallucinated_citations else GroundingStatus.UNGROUNDED
            is_grounded = status == GroundingStatus.GROUNDED
            reason = "No claims detected."
        elif len(verified_citations) == 0 and len(all_citations) == 0 and any(c.is_critical for c in analyzed_claims):
            # Critical claims exist but zero citations provided
            status = GroundingStatus.UNGROUNDED
            is_grounded = False
            reason = "Critical claims lack evidence citations."
        elif hallucinated_citations:
            status = GroundingStatus.UNGROUNDED if len(verified_citations) == 0 else GroundingStatus.PARTIALLY_GROUNDED
            is_grounded = False
            reason = f"Hallucinated evidence citations detected: {', '.join(hallucinated_citations)}"
        elif ungrounded_count > 0:
            status = GroundingStatus.PARTIALLY_GROUNDED
            is_grounded = False
            reason = f"{ungrounded_count} ungrounded assertions detected."
        else:
            status = GroundingStatus.GROUNDED
            is_grounded = True
            reason = "All claims and citations grounded in verified evidence."

        # Generate sanitized text by filtering ungrounded assertions
        sanitized = self.strip_ungrounded_assertions(text, valid_ids)

        return GroundingResult(
            status=status,
            is_grounded=is_grounded,
            citations=all_citations,
            verified_citations=verified_citations,
            hallucinated_citations=hallucinated_citations,
            total_claims=len(claims_raw),
            grounded_claims=grounded_count,
            ungrounded_claims=ungrounded_count,
            claims=analyzed_claims,
            sanitized_text=sanitized,
            reason=reason,
        )

    def strip_ungrounded_assertions(
        self,
        text: str,
        valid_ids: set[str],
    ) -> str:
        """Strip claims containing hallucinated citations or ungrounded critical assertions."""
        lines = text.split("\n")
        filtered_lines: list[str] = []

        for line in lines:
            line_citations = self.extract_citations(line)
            # If line has hallucinated citations, skip it
            if any(c not in valid_ids for c in line_citations):
                continue

            # If line is a critical assertion without any citation, flag or strip
            clean_line = line.strip()
            if clean_line and self.is_critical_claim(clean_line) and not line_citations:
                continue

            filtered_lines.append(line)

        return "\n".join(filtered_lines)

    def format_evidence_context(self, evidence_list: list[Evidence]) -> str:
        """Format verified evidence items into strict context lines for LLM prompts."""
        lines = []
        for ev in evidence_list:
            actor = ev.authenticated_actor or "anonymous"
            owner = ev.resource_owner or "unknown"
            obs = ev.observation or "No observation"
            lines.append(
                f"- [{ev.id}] {ev.request_method} {ev.request_path} -> "
                f"HTTP {ev.response_status} (Actor: {actor}, Resource Owner: {owner}) | {obs}"
            )
        return "\n".join(lines)

    def bind_prompt(
        self,
        finding: Finding,
        evidence_list: list[Evidence],
        instruction: Optional[str] = None
    ) -> str:
        """Construct a prompt strictly binding the AI to verified evidence IDs."""
        ev_context = self.format_evidence_context(evidence_list)
        allowed_ids = ", ".join(f"[{ev.id}]" for ev in evidence_list)

        base_instruction = instruction or (
            "Explain this finding based strictly on the verified evidence below. "
            "You MUST cite exact evidence IDs (e.g., [E01], [E02]) for every factual claim. "
            "Do NOT reference unobserved actions, external targets, or hallucinated evidence."
        )

        prompt = (
            f"You are the RAVEN AI Security Analyst & Tutor.\n\n"
            f"=== TARGET FINDING ===\n"
            f"Vulnerability: {finding.vulnerability_type}\n"
            f"Endpoint: {finding.endpoint}\n"
            f"Severity: {finding.severity}\n\n"
            f"=== VERIFIED EVIDENCE STORE ({len(evidence_list)} items) ===\n"
            f"{ev_context}\n\n"
            f"=== GROUNDING MANDATE ===\n"
            f"Permitted Evidence Citations: {allowed_ids}\n"
            f"{base_instruction}\n"
        )
        return prompt
