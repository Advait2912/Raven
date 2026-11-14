"""Progressive Hint Engine for RAVEN Trustworthy AI.

Pedagogical scaffolding for Student Mode:
- 3-Tier progressive hints: Tier 1 (Conceptual) -> Tier 2 (Observational) -> Tier 3 (Actionable)
- Enforces strict pacing and prerequisite constraints: Tier N+1 cannot be unlocked without
  having viewed Tier N and spent at least 30 seconds on that step.
"""

import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Dict, List, Optional
from raven.core.models import Evidence


class HintTier(IntEnum):
    """The 3 pedagogical hint tiers."""
    CONCEPTUAL = 1     # Explains vulnerability class without naming endpoints/parameters
    OBSERVATIONAL = 2  # Directs attention to specific telemetry in traffic logs
    ACTIONABLE = 3     # Suggests specific test or parameter modification to verify


@dataclass
class HintResult:
    """The outcome of a hint request."""
    tier: int
    tier_name: str
    unlocked: bool
    title: str
    content: str
    cooldown_remaining: float = 0.0
    message: Optional[str] = None
    unlocked_tiers: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier,
            "tier_name": self.tier_name,
            "unlocked": self.unlocked,
            "title": self.title,
            "content": self.content,
            "cooldown_remaining": self.cooldown_remaining,
            "message": self.message,
            "unlocked_tiers": self.unlocked_tiers,
        }


@dataclass
class SessionState:
    """Tracks hint unlocking and viewing timestamps for a student session."""
    session_id: str
    viewed_timestamps: dict[int, float] = field(default_factory=dict)

    def is_tier_viewed(self, tier: int) -> bool:
        return tier in self.viewed_timestamps

    def get_view_time(self, tier: int) -> Optional[float]:
        return self.viewed_timestamps.get(tier)

    def record_view(self, tier: int, timestamp: float) -> None:
        if tier not in self.viewed_timestamps:
            self.viewed_timestamps[tier] = timestamp

    def get_unlocked_tiers(self) -> list[int]:
        return sorted(list(self.viewed_timestamps.keys()))


class ProgressiveHintEngine:
    """Pedagogical engine enforcing structured 3-tier scaffolding and pacing."""

    DEFAULT_COOLDOWN_SECONDS = 30.0

    TIER_NAMES = {
        HintTier.CONCEPTUAL: "Conceptual",
        HintTier.OBSERVATIONAL: "Observational",
        HintTier.ACTIONABLE: "Actionable",
    }

    # Default knowledge base for IDOR
    IDOR_HINTS = {
        HintTier.CONCEPTUAL: {
            "title": "Tier 1 (Conceptual): Object-Level Authorization",
            "content": (
                "Think about how the application verifies that the requester owns the requested resource ID. "
                "Does receiving an object identifier in a request mean the server should trust that "
                "the authenticated actor has permission to access it? What validation must take place "
                "between fetching the record and returning the response?"
            ),
        },
        HintTier.OBSERVATIONAL: {
            "title": "Tier 2 (Observational): Telemetry & Identity Discrepancy",
            "content": (
                "Examine the telemetry in your HTTP traffic logs. Observe request E01 where Alice "
                "retrieves order 101 (belonging to usr_alice). Then observe request E02 where the order "
                "parameter is changed to 102. Compare the authenticated actor in the bearer token "
                "with the resource owner returned in the JSON payload."
            ),
        },
        HintTier.ACTIONABLE: {
            "title": "Tier 3 (Actionable): Parameter Tampering Verification",
            "content": (
                "To confirm the Broken Object-Level Authorization (IDOR) flaw: send a GET request "
                "to `/api/orders/102` using Alice's Authorization bearer token. If the response returns "
                "HTTP 200 OK with Bob's confidential order details (`owner_id: usr_bob`), unauthorized "
                "horizontal access is proven."
            ),
        },
    }

    def __init__(
        self,
        min_delay_seconds: float = DEFAULT_COOLDOWN_SECONDS,
        time_provider: Optional[Callable[[], float]] = None,
    ) -> None:
        self.min_delay_seconds = min_delay_seconds
        self._time_provider = time_provider or time.time
        self._sessions: dict[str, SessionState] = {}

    def _get_session(self, session_id: str) -> SessionState:
        if session_id not in self._sessions:
            self._sessions[session_id] = SessionState(session_id=session_id)
        return self._sessions[session_id]

    def reset_session(self, session_id: str = "default") -> None:
        """Reset student progression for a session."""
        if session_id in self._sessions:
            del self._sessions[session_id]

    def can_unlock(
        self,
        tier: int,
        session_id: str = "default",
    ) -> tuple[bool, float, Optional[str]]:
        """Check whether tier N can be unlocked based on prerequisites and 30s delay.
        
        Returns:
            (can_unlock: bool, cooldown_remaining: float, reason_if_locked: Optional[str])
        """
        if tier not in (HintTier.CONCEPTUAL, HintTier.OBSERVATIONAL, HintTier.ACTIONABLE):
            return False, 0.0, f"Invalid hint tier: {tier}. Must be 1, 2, or 3."

        session = self._get_session(session_id)
        current_time = self._time_provider()

        # Tier 1 is always unlockable
        if tier == HintTier.CONCEPTUAL:
            return True, 0.0, None

        # Tier N requires Tier N-1 to have been viewed
        prev_tier = tier - 1
        prev_view_time = session.get_view_time(prev_tier)

        if prev_view_time is None:
            prev_name = self.TIER_NAMES[HintTier(prev_tier)]
            curr_name = self.TIER_NAMES[HintTier(tier)]
            return (
                False,
                0.0,
                f"Prerequisite locked: You must view and study Tier {prev_tier} ({prev_name}) "
                f"before unlocking Tier {tier} ({curr_name}).",
            )

        # Tier N requires at least min_delay_seconds elapsed since viewing Tier N-1
        elapsed = current_time - prev_view_time
        if elapsed < self.min_delay_seconds:
            remaining = round(self.min_delay_seconds - elapsed, 1)
            prev_name = self.TIER_NAMES[HintTier(prev_tier)]
            return (
                False,
                remaining,
                f"Pacing guardrail: Please spend at least {self.min_delay_seconds:.0f} seconds "
                f"analyzing Tier {prev_tier} ({prev_name}) before progressing. "
                f"{remaining:.1f}s remaining.",
            )

        return True, 0.0, None

    def get_hint(
        self,
        tier: int,
        session_id: str = "default",
        vulnerability_type: str = "IDOR",
        evidence_list: Optional[list[Evidence]] = None,
        custom_hints: Optional[dict[int, dict[str, str]]] = None,
    ) -> HintResult:
        """Fetch progressive hint at requested tier enforcing pedagogical progression."""
        if tier not in (1, 2, 3):
            return HintResult(
                tier=tier,
                tier_name="Unknown",
                unlocked=False,
                title="Invalid Tier",
                content="",
                message=f"Hint tier {tier} does not exist. Available tiers are 1, 2, 3.",
            )

        hint_tier = HintTier(tier)
        tier_name = self.TIER_NAMES[hint_tier]
        session = self._get_session(session_id)
        current_time = self._time_provider()

        allowed, remaining, reason = self.can_unlock(tier, session_id=session_id)

        if not allowed:
            return HintResult(
                tier=tier,
                tier_name=tier_name,
                unlocked=False,
                title=f"Tier {tier} ({tier_name}) — Locked",
                content="This hint is currently locked to encourage active reasoning.",
                cooldown_remaining=remaining,
                message=reason,
                unlocked_tiers=session.get_unlocked_tiers(),
            )

        # Mark tier as viewed
        session.record_view(tier, current_time)

        # Retrieve content from custom or default store
        hints_repo = custom_hints or self.IDOR_HINTS
        hint_data = hints_repo.get(hint_tier, self.IDOR_HINTS[hint_tier])

        # If evidence_list is provided and tier == 2 (Observational), enrich with live evidence IDs
        content = hint_data["content"]
        if tier == HintTier.OBSERVATIONAL and evidence_list:
            ev_ids = [e.id for e in evidence_list]
            if ev_ids:
                content += f"\n\nActive Evidence IDs recorded in session: {', '.join(ev_ids)}."

        return HintResult(
            tier=tier,
            tier_name=tier_name,
            unlocked=True,
            title=hint_data["title"],
            content=content,
            cooldown_remaining=0.0,
            message="Hint successfully unlocked.",
            unlocked_tiers=session.get_unlocked_tiers(),
        )
