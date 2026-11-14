"""AI Output Verifier for RAVEN Trustworthy AI.

Deterministic post-generation firewall:
- Schema validation (structured JSON & markdown contracts)
- Prohibited patterns defense (out-of-scope targets, dangerous bash commands, unauthorized bypass advice)
- Fail-closed fallback mechanism
"""

import json
import re
from dataclasses import dataclass, field
from typing import Any, List, Optional, Set, Union
from raven.core.policy import Scope


@dataclass
class VerificationResult:
    """Outcome of deterministic AI output verification."""
    is_valid: bool
    violations: list[str]
    output: str
    raw_output: str
    fallback_used: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "violations": self.violations,
            "output": self.output,
            "fallback_used": self.fallback_used,
        }


class AIOutputVerifier:
    """Post-generation deterministic firewall for AI responses."""

    DEFAULT_FALLBACK = (
        "The AI-generated response was rejected by RAVEN's deterministic output verifier "
        "because it violated safety policies, contained prohibited commands, or failed schema validation. "
        "RAVEN enforces a strict fail-closed boundary to ensure all actions and guidance remain "
        "safe and contained within authorized lab parameters. "
        "Please review the verified lab telemetry and findings directly."
    )

    # Prohibited dangerous shell/system commands
    DANGEROUS_COMMAND_PATTERNS = [
        # Destructive filesystem
        re.compile(r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|--recursive\s+--force)\b", re.IGNORECASE),
        re.compile(r"\brm\s+(-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*)\b", re.IGNORECASE),
        re.compile(r"\brm\s+-[rR]\s+/[^\s]*", re.IGNORECASE),
        re.compile(r"\bmkfs(\.[a-zA-Z0-9]+)?\b", re.IGNORECASE),
        re.compile(r"\bdd\s+if=/dev/(zero|urandom|random)\s+of=/dev/[a-zA-Z0-9]+", re.IGNORECASE),
        re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", re.IGNORECASE),  # fork bomb
        re.compile(r"\bchmod\s+(-R\s+)?777\s+/", re.IGNORECASE),
        re.compile(r"\bchown\s+-R\b.*root", re.IGNORECASE),
        re.compile(r"\bformat\s+[a-zA-Z]:", re.IGNORECASE),
        re.compile(r"\bdel\s+/[fF]\s+/[sS]\s+/[qQ]\b", re.IGNORECASE),
        # Raw socket fuzzing and listener binding
        re.compile(r"\bnc(\.traditional)?\s+(-[a-zA-Z]*[le][a-zA-Z]*)\b", re.IGNORECASE),
        re.compile(r"\bncat\s+(-[a-zA-Z]*[le][a-zA-Z]*)\b", re.IGNORECASE),
        re.compile(r"\bsocat\b", re.IGNORECASE),
        re.compile(r"/dev/tcp/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+", re.IGNORECASE),
        re.compile(r"/dev/udp/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+", re.IGNORECASE),
        re.compile(r"\bSOCK_RAW\b", re.IGNORECASE),
        re.compile(r"\bhping3\b", re.IGNORECASE),
        # Shell pipes
        re.compile(r"curl\s+[^|]+\|\s*(ba|z|t?c)?sh\b", re.IGNORECASE),
        re.compile(r"wget\s+[^|]+\|\s*(ba|z|t?c)?sh\b", re.IGNORECASE),
        # Reverse shells
        re.compile(r"bash\s+-i\s+>&?\s*/dev/tcp/", re.IGNORECASE),
        re.compile(r"python(\d)?\s+-c\s+['\"].*socket.*subprocess.*['\"]", re.IGNORECASE),
    ]

    # Prohibited out-of-scope targets and cloud metadata
    OUT_OF_SCOPE_TARGET_PATTERNS = [
        re.compile(r"\b169\.254\.169\.254\b"),
        re.compile(r"\b169\.254\.\d{1,3}\.\d{1,3}\b"),
        re.compile(r"\bmetadata\.google\.internal\b", re.IGNORECASE),
        re.compile(r"\bmetadata\.azure\.internal\b", re.IGNORECASE),
        re.compile(r"\b(evil|attacker|malicious-site|pwned)\.com\b", re.IGNORECASE),
        re.compile(r"\b[a-zA-Z0-9-]+\.(oastify|burpcollaborator|interactsh)\.(com|net)\b", re.IGNORECASE),
    ]

    # Prohibited guidance instructing students to bypass authorization outside the lab
    UNAUTHORIZED_GUIDANCE_PATTERNS = [
        re.compile(r"bypass\s+authorization(\s+controls)?\s+outside(\s+the)?\s+lab", re.IGNORECASE),
        re.compile(r"test\s+(this|these|the)?\s*(attack|exploit|vulnerability|flaw)?s?\s*(against|on)\s+(production|live|real-world|external)\s+(systems?|servers?|targets?|networks?)", re.IGNORECASE),
        re.compile(r"exploit\s+without\s+(explicit\s+)?(authorization|permission|consent)", re.IGNORECASE),
        re.compile(r"attack\s+(your\s+company|external\s+targets?|third-party|unauthorized)", re.IGNORECASE),
        re.compile(r"disable\s+(production|external)\s+(firewalls?|controls?|safeguards?)", re.IGNORECASE),
        re.compile(r"ignore\s+(scope|authorization)\s+boundaries", re.IGNORECASE),
    ]

    def __init__(self, fallback_message: Optional[str] = None) -> None:
        self.fallback_message = fallback_message or self.DEFAULT_FALLBACK

    def check_prohibited_patterns(
        self,
        text: str,
        allowed_domains: Optional[list[str]] = None,
    ) -> list[str]:
        """Detect prohibited commands, out-of-scope targets, and unauthorized guidance."""
        violations: list[str] = []

        # 1. Dangerous command check
        for pattern in self.DANGEROUS_COMMAND_PATTERNS:
            match = pattern.search(text)
            if match:
                violations.append(f"Prohibited dangerous command detected: '{match.group(0)}'")

        # 2. Out-of-scope targets and cloud metadata
        for pattern in self.OUT_OF_SCOPE_TARGET_PATTERNS:
            match = pattern.search(text)
            if match:
                violations.append(f"Prohibited out-of-scope target detected: '{match.group(0)}'")

        # Domain boundary check if allowed_domains is provided
        if allowed_domains:
            allowed_set = {d.lower().strip() for d in allowed_domains}
            # Find URLs or domain-like strings in text
            found_urls = re.findall(r"https?://([a-zA-Z0-9.-]+)", text)
            for domain in found_urls:
                d_lower = domain.lower()
                if d_lower not in allowed_set and not any(d_lower.endswith(f".{a}") for a in allowed_set):
                    violations.append(f"Target domain '{domain}' is outside authorized scope {allowed_domains}")

        # 3. Unauthorized guidance check
        for pattern in self.UNAUTHORIZED_GUIDANCE_PATTERNS:
            match = pattern.search(text)
            if match:
                violations.append(f"Prohibited advice detected: instruction to bypass authorization outside lab ('{match.group(0)}')")

        return violations

    def validate_schema(
        self,
        data: Union[str, dict[str, Any]],
        expected_keys: Optional[list[str]] = None,
        required_sections: Optional[list[str]] = None,
    ) -> list[str]:
        """Validate JSON schema or markdown structure."""
        violations: list[str] = []

        if isinstance(data, dict):
            # Dict schema validation
            if expected_keys:
                missing = [k for k in expected_keys if k not in data]
                if missing:
                    violations.append(f"Schema violation: missing required keys: {missing}")
            return violations

        # String data: check if it's meant to be JSON
        text = data.strip()
        if expected_keys is not None:
            # Expected to parse as JSON dict
            try:
                parsed = json.loads(text)
                if not isinstance(parsed, dict):
                    violations.append("Schema violation: output must be a JSON object.")
                else:
                    missing = [k for k in expected_keys if k not in parsed]
                    if missing:
                        violations.append(f"Schema violation: missing required JSON keys: {missing}")
            except Exception as e:
                violations.append(f"Schema violation: invalid JSON format ({str(e)})")
            return violations

        # Check markdown integrity
        # 1. Unclosed code blocks (odd number of ```)
        backtick_blocks = len(re.findall(r"```", text))
        if backtick_blocks % 2 != 0:
            violations.append("Markdown syntax violation: unclosed code block detected.")

        # 2. Check required sections if specified
        if required_sections:
            text_lower = text.lower()
            missing_sections = [
                s for s in required_sections if s.lower() not in text_lower
            ]
            if missing_sections:
                violations.append(f"Markdown contract violation: missing required sections: {missing_sections}")

        return violations

    def verify(
        self,
        output: Union[str, dict[str, Any]],
        expected_keys: Optional[list[str]] = None,
        required_sections: Optional[list[str]] = None,
        allowed_domains: Optional[list[str]] = None,
        scope: Optional[Scope] = None,
        custom_fallback: Optional[str] = None,
    ) -> VerificationResult:
        """Deterministically verify AI output against schema and safety policies.
        
        Fail-closed: Returns fallback explanation on ANY violation.
        """
        raw_str = json.dumps(output) if isinstance(output, dict) else str(output)
        violations: list[str] = []

        # 1. Schema check
        schema_violations = self.validate_schema(
            output,
            expected_keys=expected_keys,
            required_sections=required_sections,
        )
        violations.extend(schema_violations)

        # 2. Scope resolution
        effective_allowed_domains = allowed_domains
        if scope and not effective_allowed_domains:
            effective_allowed_domains = scope.allowed_domains

        # 3. Prohibited patterns check
        pattern_violations = self.check_prohibited_patterns(
            raw_str,
            allowed_domains=effective_allowed_domains,
        )
        violations.extend(pattern_violations)

        # Fail-closed enforcement
        if violations:
            fallback = custom_fallback or self.fallback_message
            return VerificationResult(
                is_valid=False,
                violations=violations,
                output=fallback,
                raw_output=raw_str,
                fallback_used=True,
            )

        return VerificationResult(
            is_valid=True,
            violations=[],
            output=raw_str,
            raw_output=raw_str,
            fallback_used=False,
        )
