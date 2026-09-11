# Unit tests for IDOR attack execution and deterministic validation.

import pytest
from attack.idor import IDORAttack
from raven.core.store import EvidenceStore
from raven.target.lab import VulnerableLabTarget


def test_idor_attack_success() -> None:
    target = VulnerableLabTarget()
    store = EvidenceStore()
    attack = IDORAttack()

    result = attack.execute(target, store)

    assert result.success is True
    assert result.status == "VULNERABILITY_CONFIRMED"
    assert len(result.evidence) == 2
    assert result.evidence[0].id == "E01"
    assert result.evidence[1].id == "E02"
    assert len(result.findings) == 1
    assert result.findings[0].vulnerability_type == "Insecure Direct Object Reference (IDOR)"


def test_idor_attack_on_patched_target() -> None:
    target = VulnerableLabTarget()
    target.is_vulnerable = False  # Patched!
    store = EvidenceStore()
    attack = IDORAttack()

    result = attack.execute(target, store)

    assert result.success is False
    assert result.status == "VULNERABILITY_NOT_DETECTED"
    assert len(result.findings) == 0
