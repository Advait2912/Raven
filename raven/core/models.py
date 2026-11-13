# Core data models for RAVEN.
# Design choice: keep data structures typed, transparent, and serializable
# so evidence and findings can be deterministically verified and inspected.

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class FindingStatus(str, Enum):
    """Deterministic 5-state lifecycle for vulnerability findings.

    Only deterministic FindingValidator code paths may transition states.
    AI components NEVER transition finding states.
    """
    NOT_TESTED = "NOT_TESTED"
    NOT_DETECTED = "NOT_DETECTED"
    UNCONFIRMED = "UNCONFIRMED"
    CONFIRMED = "CONFIRMED"
    INVALIDATED = "INVALIDATED"


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
    Cryptographically chained via HMAC-SHA256 and redacted before storage.
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
    # V1 Extensions
    assessment_id: str = "default"
    response_headers: dict[str, str] = field(default_factory=dict)
    chain_hash: Optional[str] = None
    recorded_at: Optional[str] = None

    def __post_init__(self) -> None:
        if self.recorded_at is None:
            self.recorded_at = self.timestamp

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
    confirmed: bool = True
    impact: str = ""
    root_cause: str = ""
    remediation: str = ""
    # V1 Extensions
    status: FindingStatus = FindingStatus.CONFIRMED
    confidence: float = 1.0
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    assessment_id: str = "default"

    def __post_init__(self) -> None:
        if isinstance(self.status, str):
            try:
                self.status = FindingStatus(self.status)
            except ValueError:
                self.status = FindingStatus.CONFIRMED if self.confirmed else FindingStatus.NOT_DETECTED
        # Keep confirmed flag in sync
        if self.status == FindingStatus.CONFIRMED:
            self.confirmed = True
        elif self.status in (FindingStatus.NOT_DETECTED, FindingStatus.INVALIDATED):
            self.confirmed = False

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value if isinstance(self.status, FindingStatus) else str(self.status)
        return d


@dataclass
class ScopeViolation:
    """Record of an attempted request that was blocked by security controls."""
    id: str
    violation_type: str  # DOMAIN_OUT_OF_SCOPE | PRIVATE_IP | BUDGET_EXCEEDED | DNS_REBINDING | METHOD_NOT_ALLOWED | PATH_NOT_ALLOWED
    attempted_target: str
    blocked_by: str       # PolicyGate | NetworkGateway
    details: str = ""
    assessment_id: str = "default"
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

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
