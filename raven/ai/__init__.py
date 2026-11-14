"""AI reasoning, verification, and tutoring components for RAVEN.

Provides:
- OllamaClient: Local LLM interaction
- EvidenceGrounder: Binds prompts and verifies citations against EvidenceStore
- AIOutputVerifier: Deterministic post-generation safety and schema firewall
- ConfidenceAnnotator: Mathematical confidence calibration and bounding
- ProgressiveHintEngine: 3-tier progressive pedagogical hints with time guardrails
- AITutor: High-level tutor synthesizing verified AI explanations and scaffolding
"""

from .confidence import ConfidenceAnnotator, ConfidenceResult
from .grounder import ClaimAssertion, EvidenceGrounder, GroundingResult, GroundingStatus
from .hints import HintResult, HintTier, ProgressiveHintEngine
from .ollama import OllamaClient
from .tutor import AITutor
from .verifier import AIOutputVerifier, VerificationResult

__all__ = [
    "AITutor",
    "AIOutputVerifier",
    "ClaimAssertion",
    "ConfidenceAnnotator",
    "ConfidenceResult",
    "EvidenceGrounder",
    "GroundingResult",
    "GroundingStatus",
    "HintResult",
    "HintTier",
    "OllamaClient",
    "ProgressiveHintEngine",
    "VerificationResult",
]
