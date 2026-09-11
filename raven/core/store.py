# In-memory evidence store.
# Design choice: stable sequential IDs (E01, E02...) to enable clear citation
# by deterministic validators and the AI reasoner.

from typing import Optional
from .models import Evidence, Finding, Observation


class EvidenceStore:
    """Thread-safe store for recorded evidence and observations."""

    def __init__(self) -> None:
        self._evidence: list[Evidence] = []
        self._observations: list[Observation] = []
        self._findings: list[Finding] = []
        self._counter: int = 0

    def next_id(self) -> str:
        """Generate a stable sequential ID like E01, E02, etc."""
        self._counter += 1
        return f"E{self._counter:02d}"

    def add_evidence(self, evidence: Evidence) -> None:
        self._evidence.append(evidence)

    def add_observation(self, observation: Observation) -> None:
        self._observations.append(observation)

    def add_finding(self, finding: Finding) -> None:
        self._findings.append(finding)

    def get_evidence(self, evidence_id: str) -> Optional[Evidence]:
        for item in self._evidence:
            if item.id == evidence_id:
                return item
        return None

    def get_all_evidence(self) -> list[Evidence]:
        return list(self._evidence)

    def get_all_observations(self) -> list[Observation]:
        return list(self._observations)

    def get_all_findings(self) -> list[Finding]:
        return list(self._findings)

    def clear(self) -> None:
        self._evidence.clear()
        self._observations.clear()
        self._findings.clear()
        self._counter = 0
