"""Unit and integration test suite for RAVEN Trustworthy AI subsystem.

Tests:
1. EvidenceGrounder:
   - Citation extraction from text
   - Cross-referencing against EvidenceStore
   - Hallucinated citation detection
   - Zero citations for critical claims -> UNGROUNDED
   - Stripping and sanitizing ungrounded claims
   - Prompt binding strictly to verified evidence IDs
2. AIOutputVerifier:
   - Schema validation (JSON dict keys, invalid syntax, markdown code blocks)
   - Prohibited commands (rm -rf, raw socket fuzzing, reverse shells)
   - Out-of-scope targets (169.254.169.254, evil.com)
   - Advice to bypass authorization controls outside lab
   - Fail-closed fallback guarantee
3. ConfidenceAnnotator:
   - Mathematical grounding ratio
   - Severity alignment: bounded when evidence is baseline-only vs differential
   - Rejection and overriding of arbitrary LLM self-reported confidence
4. ProgressiveHintEngine:
   - 3-tier progressive unlocking (Conceptual -> Observational -> Actionable)
   - Pacing guardrail: Tier N+1 locked before 30 seconds elapsed
   - Prerequisite guardrail: Tier N+1 locked before Tier N viewed
   - Reset and session isolation
5. AITutor End-to-End:
   - Mocked clean response
   - Mocked dangerous/prohibited output -> fail-closed fallback
   - Mocked hallucinated output -> fail-closed fallback
"""

import json
from unittest.mock import MagicMock
import pytest
from raven.ai.confidence import ConfidenceAnnotator, ConfidenceResult
from raven.ai.grounder import ClaimAssertion, EvidenceGrounder, GroundingResult, GroundingStatus
from raven.ai.hints import HintResult, HintTier, ProgressiveHintEngine
from raven.ai.ollama import OllamaClient
from raven.ai.tutor import AITutor
from raven.ai.verifier import AIOutputVerifier, VerificationResult
from raven.core.models import Evidence, Finding, FindingStatus
from raven.core.policy import Scope
from raven.core.store import EvidenceStore


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_evidence_baseline():
    return Evidence(
        id="E01",
        evidence_type="HTTP_BASELINE_ACCESS",
        request_method="GET",
        request_path="/api/orders/101",
        request_headers={"Authorization": "Bearer alice_token"},
        request_body=None,
        response_status=200,
        response_body={"order_id": 101, "owner_id": "usr_alice", "item": "Keyboard"},
        authenticated_actor="usr_alice",
        resource_owner="usr_alice",
        observation="Legitimate baseline access to own order 101.",
    )


@pytest.fixture
def sample_evidence_tamper():
    return Evidence(
        id="E02",
        evidence_type="HTTP_TAMPER_ACCESS",
        request_method="GET",
        request_path="/api/orders/102",
        request_headers={"Authorization": "Bearer alice_token"},
        request_body=None,
        response_status=200,
        response_body={"order_id": 102, "owner_id": "usr_bob", "item": "Confidential Report"},
        authenticated_actor="usr_alice",
        resource_owner="usr_bob",
        observation="Tampered request to order 102 returned Bob's data with HTTP 200.",
    )


@pytest.fixture
def sample_finding():
    return Finding(
        id="F01",
        vulnerability_type="Insecure Direct Object Reference (IDOR)",
        severity="HIGH",
        endpoint="/api/orders/102",
        evidence_ids=["E01", "E02"],
        confirmed=True,
        impact="Unauthorized horizontal reading of confidential customer orders.",
        root_cause="Missing authorization check verifying order.owner_id == session.user_id.",
        status=FindingStatus.CONFIRMED,
        confidence=1.0,
    )


@pytest.fixture
def evidence_store_with_items(sample_evidence_baseline, sample_evidence_tamper):
    store = EvidenceStore()
    store.add_evidence(sample_evidence_baseline)
    store.add_evidence(sample_evidence_tamper)
    return store


# ---------------------------------------------------------------------------
# 1. EvidenceGrounder Tests
# ---------------------------------------------------------------------------

class TestEvidenceGrounder:

    def test_extract_bracketed_and_word_citations(self):
        grounder = EvidenceGrounder()
        text = "As shown in [E01], Alice requested order 101. Later in request E02, Bob's order was accessed. See also [e03]."
        citations = grounder.extract_citations(text)
        assert citations == ["E01", "E03", "E02"]

    def test_bind_prompt_contains_evidence_ids_and_strict_mandate(self, sample_finding, sample_evidence_baseline, sample_evidence_tamper):
        grounder = EvidenceGrounder()
        prompt = grounder.bind_prompt(sample_finding, [sample_evidence_baseline, sample_evidence_tamper])
        assert "[E01]" in prompt
        assert "[E02]" in prompt
        assert "Permitted Evidence Citations: [E01], [E02]" in prompt
        assert "GROUNDING MANDATE" in prompt
        assert sample_finding.vulnerability_type in prompt

    def test_validate_citations_clean_grounded(self, evidence_store_with_items):
        grounder = EvidenceGrounder(evidence_store_with_items)
        text = (
            "Alice successfully accessed her own order under [E01]. "
            "When requesting order 102 under [E02], the server returned Bob's record."
        )
        result = grounder.validate_citations(text)
        assert result.is_grounded is True
        assert result.status == GroundingStatus.GROUNDED
        assert set(result.verified_citations) == {"E01", "E02"}
        assert len(result.hallucinated_citations) == 0

    def test_validate_citations_hallucinated_citation_detected(self, evidence_store_with_items):
        grounder = EvidenceGrounder(evidence_store_with_items)
        # Store only has E01 and E02. E99 is a hallucinated citation!
        text = (
            "Under [E01], legitimate access occurred. "
            "In [E99], Alice escalated privileges to administrator."
        )
        result = grounder.validate_citations(text)
        assert result.is_grounded is False
        assert "E99" in result.hallucinated_citations
        assert result.status == GroundingStatus.PARTIALLY_GROUNDED
        assert "E99" in result.reason

    def test_zero_citations_for_critical_claim_marked_ungrounded(self, evidence_store_with_items):
        grounder = EvidenceGrounder(evidence_store_with_items)
        # Text makes critical security assertions with zero evidence citations
        text = (
            "The application suffers from critical unauthorized access. "
            "Alice tampered with the ID and accessed confidential data from Bob."
        )
        result = grounder.validate_citations(text)
        assert result.is_grounded is False
        assert result.status == GroundingStatus.UNGROUNDED
        assert len(result.verified_citations) == 0
        assert "lack evidence citations" in result.reason

    def test_strip_ungrounded_assertions(self, evidence_store_with_items):
        grounder = EvidenceGrounder(evidence_store_with_items)
        text = (
            "- [E01] Legitimate access verified.\n"
            "- [E99] Alice deleted all database records without permission.\n"
            "- Critical unauthorized access observed without citation.\n"
            "- [E02] Tampered access returned HTTP 200."
        )
        sanitized = grounder.strip_ungrounded_assertions(text, valid_ids={"E01", "E02"})
        assert "[E01]" in sanitized
        assert "[E02]" in sanitized
        assert "E99" not in sanitized
        assert "deleted all database records" not in sanitized


# ---------------------------------------------------------------------------
# 2. AIOutputVerifier Tests
# ---------------------------------------------------------------------------

class TestAIOutputVerifier:

    def test_clean_output_passes_verification(self):
        verifier = AIOutputVerifier()
        clean_text = (
            "### Finding Explanation\n"
            "An IDOR vulnerability was verified on `/api/orders/{id}`.\n"
            "The server did not enforce object-level authorization checks."
        )
        res = verifier.verify(clean_text)
        assert res.is_valid is True
        assert res.fallback_used is False
        assert res.output == clean_text
        assert len(res.violations) == 0

    def test_prohibited_bash_rm_rf_fails_closed(self):
        verifier = AIOutputVerifier()
        dangerous_output = (
            "To clean up the test environment, run:\n"
            "```bash\nrm -rf /tmp/data\n```\n"
            "This will reset your files."
        )
        res = verifier.verify(dangerous_output)
        assert res.is_valid is False
        assert res.fallback_used is True
        assert verifier.DEFAULT_FALLBACK in res.output
        assert any("rm" in v.lower() for v in res.violations)

    def test_prohibited_raw_socket_fuzzing_fails_closed(self):
        verifier = AIOutputVerifier()
        dangerous_output = (
            "Listen for inbound connections using:\n"
            "`nc -lvnp 4444`\n"
            "or pipe packets to `/dev/tcp/10.0.0.1/80`."
        )
        res = verifier.verify(dangerous_output)
        assert res.is_valid is False
        assert res.fallback_used is True
        assert any("nc" in v.lower() or "tcp" in v.lower() for v in res.violations)

    def test_prohibited_out_of_scope_target_fails_closed(self):
        verifier = AIOutputVerifier()
        metadata_output = (
            "Try retrieving cloud credentials by querying `http://169.254.169.254/latest/meta-data/`."
        )
        res = verifier.verify(metadata_output)
        assert res.is_valid is False
        assert res.fallback_used is True
        assert any("169.254.169.254" in v for v in res.violations)

    def test_prohibited_external_domain_fails_closed(self):
        verifier = AIOutputVerifier()
        external_output = "Send the extracted token to `https://evil.com/exfiltrate`."
        res = verifier.verify(external_output)
        assert res.is_valid is False
        assert res.fallback_used is True
        assert any("evil.com" in v for v in res.violations)

    def test_prohibited_advice_to_bypass_authorization_outside_lab_fails_closed(self):
        verifier = AIOutputVerifier()
        advice_output = (
            "Now that you understand this technique, you can bypass authorization controls outside the lab "
            "and test this against production systems to find real bugs."
        )
        res = verifier.verify(advice_output)
        assert res.is_valid is False
        assert res.fallback_used is True
        assert any("outside lab" in v.lower() or "bypass authorization" in v.lower() for v in res.violations)

    def test_schema_validation_missing_keys_fails_closed(self):
        verifier = AIOutputVerifier()
        incomplete_json = json.dumps({"explanation": "Some explanation"})
        res = verifier.verify(
            incomplete_json,
            expected_keys=["finding_id", "explanation", "remediation"],
        )
        assert res.is_valid is False
        assert res.fallback_used is True
        assert any("missing required JSON keys" in v for v in res.violations)

    def test_schema_validation_invalid_json_syntax_fails_closed(self):
        verifier = AIOutputVerifier()
        invalid_json = "{'finding_id': 123, invalid_syntax...}"
        res = verifier.verify(invalid_json, expected_keys=["finding_id"])
        assert res.is_valid is False
        assert res.fallback_used is True
        assert any("invalid JSON format" in v for v in res.violations)

    def test_markdown_unclosed_code_blocks_fails_closed(self):
        verifier = AIOutputVerifier()
        malformed_markdown = "Here is the code:\n```python\nprint('hello')\n"  # missing closing ```
        res = verifier.verify(malformed_markdown)
        assert res.is_valid is False
        assert res.fallback_used is True
        assert any("unclosed code block" in v for v in res.violations)


# ---------------------------------------------------------------------------
# 3. ConfidenceAnnotator Tests
# ---------------------------------------------------------------------------

class TestConfidenceAnnotator:

    def test_grounding_score_mathematical_ratio(self):
        annotator = ConfidenceAnnotator()
        # 2 verified citations across 4 claims = 0.5
        score = annotator.calculate_grounding_score(verified_citations_count=2, total_claims_count=4)
        assert score == 0.5

        # 3 verified citations across 2 claims capped at 1.0
        score_capped = annotator.calculate_grounding_score(verified_citations_count=3, total_claims_count=2)
        assert score_capped == 1.0

        # 0 verified citations
        assert annotator.calculate_grounding_score(0, 5) == 0.0

    def test_confidence_calibrated_with_differential_evidence(self, sample_evidence_baseline, sample_evidence_tamper):
        annotator = ConfidenceAnnotator()
        evidence_list = [sample_evidence_baseline, sample_evidence_tamper]

        # 2 verified citations, 2 claims, full differential evidence (baseline + tamper)
        result = annotator.calibrate(
            verified_citations=["E01", "E02"],
            total_claims=2,
            evidence_list=evidence_list,
        )
        assert result.confidence >= 0.9
        assert result.is_bounded is False
        assert result.bounding_reason is None
        assert result.grounding_score == 1.0

    def test_severity_alignment_bounds_confidence_on_baseline_only(self, sample_evidence_baseline):
        annotator = ConfidenceAnnotator()
        # Evidence only contains legitimate baseline HTTP access (no differential tamper proof)
        evidence_list = [sample_evidence_baseline]

        result = annotator.calibrate(
            verified_citations=["E01"],
            total_claims=1,
            evidence_list=evidence_list,
        )
        # Must be strictly bounded by MAX_BASELINE_CONFIDENCE (0.35)
        assert result.confidence <= annotator.max_baseline_confidence
        assert result.is_bounded is True
        assert "lacks differential unauthorized access" in result.bounding_reason

    def test_replaces_arbitrary_llm_self_reported_confidence(self, sample_evidence_baseline, sample_evidence_tamper):
        annotator = ConfidenceAnnotator()
        evidence_list = [sample_evidence_baseline, sample_evidence_tamper]

        # LLM falsely claims 0.99 self-confidence, but has zero citations
        result = annotator.calibrate(
            verified_citations=[],
            total_claims=3,
            evidence_list=evidence_list,
            raw_llm_confidence=0.99,
        )
        # Arbitrary 0.99 is discarded and replaced with calibrated 0.0
        assert result.confidence == 0.0
        assert result.raw_llm_confidence == 0.99
        assert "Zero verified evidence citations" in result.bounding_reason


# ---------------------------------------------------------------------------
# 4. ProgressiveHintEngine Tests
# ---------------------------------------------------------------------------

class TestProgressiveHintEngine:

    def test_tier_1_conceptual_unlocked_immediately(self):
        engine = ProgressiveHintEngine()
        res = engine.get_hint(tier=1, session_id="student_1")
        assert res.unlocked is True
        assert res.tier == 1
        assert "Conceptual" in res.tier_name
        assert "Object-Level Authorization" in res.title
        # Conceptual hint does NOT disclose endpoint names or specific parameters
        assert "/api/orders/102" not in res.content

    def test_tier_2_locked_if_tier_1_not_viewed(self):
        engine = ProgressiveHintEngine()
        # Student attempts to jump straight to Tier 2
        res = engine.get_hint(tier=2, session_id="student_jump")
        assert res.unlocked is False
        assert "Prerequisite locked" in res.message
        assert res.tier == 2

    def test_tier_2_locked_before_30_second_cooldown(self):
        fake_time = 1000.0

        def time_mock():
            return fake_time

        engine = ProgressiveHintEngine(min_delay_seconds=30.0, time_provider=time_mock)
        # Unlock Tier 1 at t = 1000.0
        t1 = engine.get_hint(tier=1, session_id="student_paced")
        assert t1.unlocked is True

        # Try unlocking Tier 2 at t = 1010.0 (only 10 seconds elapsed)
        fake_time = 1010.0
        t2_early = engine.get_hint(tier=2, session_id="student_paced")
        assert t2_early.unlocked is False
        assert t2_early.cooldown_remaining == 20.0
        assert "Pacing guardrail" in t2_early.message

        # Unlock Tier 2 at t = 1030.0 (30 seconds elapsed)
        fake_time = 1030.0
        t2_ready = engine.get_hint(tier=2, session_id="student_paced")
        assert t2_ready.unlocked is True
        assert t2_ready.cooldown_remaining == 0.0
        assert "Observational" in t2_ready.tier_name
        assert "E01" in t2_ready.content or "E02" in t2_ready.content

    def test_tier_3_requires_tier_2_and_additional_30_seconds(self):
        fake_time = 100.0

        def time_mock():
            return fake_time

        engine = ProgressiveHintEngine(min_delay_seconds=30.0, time_provider=time_mock)

        # 1. View Tier 1 at t = 100
        engine.get_hint(tier=1, session_id="s1")

        # 2. View Tier 2 at t = 130
        fake_time = 130.0
        engine.get_hint(tier=2, session_id="s1")

        # 3. Attempt Tier 3 at t = 145 (15s elapsed, need 30s)
        fake_time = 145.0
        t3_early = engine.get_hint(tier=3, session_id="s1")
        assert t3_early.unlocked is False
        assert t3_early.cooldown_remaining == 15.0

        # 4. Attempt Tier 3 at t = 160 (30s elapsed since Tier 2)
        fake_time = 160.0
        t3_ready = engine.get_hint(tier=3, session_id="s1")
        assert t3_ready.unlocked is True
        assert "Actionable" in t3_ready.tier_name
        # Actionable provides specific test / endpoint instruction
        assert "/api/orders/102" in t3_ready.content or "GET" in t3_ready.content

    def test_session_isolation_and_reset(self):
        engine = ProgressiveHintEngine(min_delay_seconds=30.0)
        engine.get_hint(tier=1, session_id="alice")
        assert 1 in engine._get_session("alice").get_unlocked_tiers()
        assert len(engine._get_session("bob").get_unlocked_tiers()) == 0

        engine.reset_session("alice")
        assert len(engine._get_session("alice").get_unlocked_tiers()) == 0


# ---------------------------------------------------------------------------
# 5. AITutor Integration & Fail-Closed Tests
# ---------------------------------------------------------------------------

class TestAITutorTrustworthyIntegration:

    def test_tutor_explain_finding_with_clean_mocked_llm(self, sample_finding, sample_evidence_baseline, sample_evidence_tamper):
        mock_ollama = MagicMock(spec=OllamaClient)
        mock_ollama.is_available.return_value = True
        mock_ollama.model = "qwen2.5-coder"
        mock_ollama.generate.return_value = (
            "Based on [E01], Alice legitimately accessed order 101. "
            "Under [E02], Alice modified the ID to 102 and accessed Bob's order without authorization. "
            "Remediation requires verifying `order.owner_id == session.user_id`."
        )

        tutor = AITutor(ollama_client=mock_ollama)
        result = tutor.explain_finding(
            finding=sample_finding,
            evidence_list=[sample_evidence_baseline, sample_evidence_tamper],
            use_llm=True,
        )

        assert result["verification_passed"] is True
        assert result["is_grounded"] is True
        assert set(result["evidence_cited"]) == {"E01", "E02"}
        assert result["confidence"] >= 0.8
        assert result["model_used"] == "qwen2.5-coder"
        assert "[E01]" in result["explanation"]

    def test_tutor_explain_finding_fail_closed_on_prohibited_command(self, sample_finding, sample_evidence_baseline, sample_evidence_tamper):
        mock_ollama = MagicMock(spec=OllamaClient)
        mock_ollama.is_available.return_value = True
        mock_ollama.model = "qwen2.5-coder"
        # Dangerous command injected in LLM response
        mock_ollama.generate.return_value = (
            "We found an IDOR! Now run `rm -rf /` to clean the database, or pipe `nc -lvnp 4444` to exploit."
        )

        tutor = AITutor(ollama_client=mock_ollama)
        result = tutor.explain_finding(
            finding=sample_finding,
            evidence_list=[sample_evidence_baseline, sample_evidence_tamper],
            use_llm=True,
        )

        # Must fail-closed!
        assert result["verification_passed"] is False
        assert tutor.verifier.DEFAULT_FALLBACK in result["explanation"]
        assert len(result["violations"]) > 0

    def test_tutor_explain_finding_fail_closed_on_hallucinated_citations(self, sample_finding, sample_evidence_baseline, sample_evidence_tamper):
        mock_ollama = MagicMock(spec=OllamaClient)
        mock_ollama.is_available.return_value = True
        mock_ollama.model = "qwen2.5-coder"
        # Only hallucinated citation E99 provided for critical claim
        mock_ollama.generate.return_value = (
            "Under [E99], Alice escalated privileges to domain admin and exploited the target."
        )

        tutor = AITutor(ollama_client=mock_ollama)
        result = tutor.explain_finding(
            finding=sample_finding,
            evidence_list=[sample_evidence_baseline, sample_evidence_tamper],
            use_llm=True,
        )

        # Ungrounded output triggers fail-closed fallback
        assert result["verification_passed"] is False
        assert "fail-closed fallback activated" in result["explanation"].lower() or "rejected" in result["explanation"].lower()

    def test_tutor_deterministic_fallback_when_llm_unavailable(self, sample_finding, sample_evidence_baseline, sample_evidence_tamper):
        mock_ollama = MagicMock(spec=OllamaClient)
        mock_ollama.is_available.return_value = False

        tutor = AITutor(ollama_client=mock_ollama)
        result = tutor.explain_finding(
            finding=sample_finding,
            evidence_list=[sample_evidence_baseline, sample_evidence_tamper],
            use_llm=True,
        )

        assert result["model_used"] == "deterministic-rules-engine"
        assert result["verification_passed"] is True
        assert "IDOR (Insecure Direct Object Reference) confirmed" in result["explanation"]
        assert result["confidence"] > 0.0
