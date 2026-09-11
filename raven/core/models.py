# Core data models for RAVEN.
# Design choice: keep data structures typed, transparent, and serializable
# so evidence and findings can be deterministically verified and inspected.

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


@dataclass
class Observation:
    """An empirical observation generated from interacting with a target."""
    step: str
    action: str
    details: dict[str, Any]
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Evidence:
    """A verified evidence item with a stable identifier (e.g. E01, E02).

    Grounds all findings in concrete HTTP interactions and system state.
    """
    id: str
    evidence_type: str
    request_method: str
    request_path: str
    request_headers: dict[str, str]
    request_body: Optional[Any]
    response_status: int
    response_body: Optional[Any]
    authenticated_actor: Optional[str]
    resource_owner: Optional[str]
    observation: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    """A validated vulnerability finding confirmed by deterministic checks."""
    id: str
    vulnerability_type: str
    severity: str
    endpoint: str
    evidence_ids: list[str]
    confirmed: bool
    impact: str
    root_cause: str
    remediation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AttackResult:
    """Standardized result returned after an attack module executes."""
    attack_id: str
    attack_name: str
    success: bool
    status: str
    evidence: list[Evidence] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    telemetry: list[Observation] = field(default_factory=list)
    error_message: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_id": self.attack_id,
            "attack_name": self.attack_name,
            "success": self.success,
            "status": self.status,
            "evidence": [e.to_dict() for e in self.evidence],
            "findings": [f.to_dict() for f in self.findings],
            "telemetry": [t.to_dict() for t in self.telemetry],
            "error_message": self.error_message,
        }
