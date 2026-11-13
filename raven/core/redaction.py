# Deterministic Redaction Pipeline for RAVEN.
# Design choice: Zero raw secrets in storage or AI prompts, ever.
# Fail-closed behavior: Any redaction failure halts evidence storage.

import copy
import hashlib
import json
import re
from typing import Any, Optional
from .models import Evidence


class RedactionError(Exception):
    """Raised when redaction fails. Fail-closed guarantee halts data writes."""
    pass


class RedactionPipeline:
    """Deterministic scrubber for credentials, API keys, tokens, and PII."""

    # Sensitive header names (case-insensitive)
    SENSITIVE_HEADERS = {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "apikey",
        "api-key",
        "secret",
        "x-csrf-token",
        "x-xsrf-token",
    }

    # Sensitive key patterns in dictionaries/JSON (case-insensitive)
    SENSITIVE_KEY_REGEX = re.compile(
        r"(?i)^(.*_)?(password|passwd|pwd|secret|token|api_?key|auth_?token|access_?token|refresh_?token|private_?key|credit_?card|card_number|ssn|social_security_number)(_.*)?$"
    )

    # String patterns to match anywhere in body or raw payload
    STRING_PATTERNS = [
        # Bearer tokens & JWTs
        (re.compile(r"Bearer\s+[A-Za-z0-9\-_.]+", re.IGNORECASE), "Bearer [REDACTED:BEARER_TOKEN]"),
        (re.compile(r"eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+"), "[REDACTED:JWT]"),
        # Basic Auth
        (re.compile(r"Basic\s+[A-Za-z0-9+/=]+", re.IGNORECASE), "Basic [REDACTED:BASIC_AUTH]"),
        # AWS Access Keys
        (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED:AWS_KEY]"),
        # Private Keys
        (re.compile(r"-----BEGIN\s+([A-Z\s]+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+([A-Z\s]+)?PRIVATE\s+KEY-----"), "[REDACTED:PRIVATE_KEY]"),
        # Key-value secret assignments in text: password=..., db_password=..., api_key: ..., etc.
        (re.compile(r"(?i)\b([a-zA-Z0-9_-]*(?:password|passwd|pwd|secret|api[_-]?key|token))\s*[:=]\s*['\"]?([^'\"\s,;&]+)['\"]?"), r"\1=[REDACTED:\1]"),
        # Database URIs with embedded passwords
        (re.compile(r"(?i)([a-z0-9]+://[^:]+:)([^@]+)(@.+)"), r"\1[REDACTED:DB_PASSWORD]\3"),
    ]

    @classmethod
    def redact_string(cls, text: str) -> str:
        """Redact sensitive patterns from a raw text string."""
        if not text or not isinstance(text, str):
            return text
        try:
            result = text
            for pattern, replacement in cls.STRING_PATTERNS:
                result = pattern.sub(replacement, result)
            return result
        except Exception as e:
            raise RedactionError(f"String redaction failed: {e}") from e

    @classmethod
    def redact_headers(cls, headers: Optional[dict[str, str]]) -> dict[str, str]:
        """Redact sensitive headers and cookies."""
        if not headers or not isinstance(headers, dict):
            return {}
        try:
            cleaned: dict[str, str] = {}
            for k, v in headers.items():
                k_lower = k.lower().strip()
                if k_lower in cls.SENSITIVE_HEADERS:
                    if k_lower in ("authorization", "proxy-authorization"):
                        if v.lower().startswith("bearer "):
                            cleaned[k] = "Bearer [REDACTED:TOKEN]"
                        elif v.lower().startswith("basic "):
                            cleaned[k] = "Basic [REDACTED:CREDENTIAL]"
                        else:
                            cleaned[k] = "[REDACTED:AUTH]"
                    elif k_lower in ("cookie", "set-cookie"):
                        # Redact individual cookie values
                        cleaned[k] = cls._redact_cookie_header(v)
                    else:
                        cleaned[k] = f"[REDACTED:{k.upper()}]"
                else:
                    # Scrub value in case a token is passed in a custom header
                    cleaned[k] = cls.redact_string(str(v))
            return cleaned
        except Exception as e:
            raise RedactionError(f"Header redaction failed: {e}") from e

    @classmethod
    def _redact_cookie_header(cls, cookie_str: str) -> str:
        """Redact individual sensitive cookies like session, token, jwt."""
        parts = cookie_str.split(";")
        redacted_parts = []
        for part in parts:
            part = part.strip()
            if "=" in part:
                cname, cval = part.split("=", 1)
                cname_clean = cname.strip().lower()
                if any(s in cname_clean for s in ("sess", "token", "jwt", "auth", "key", "id")):
                    redacted_parts.append(f"{cname.strip()}=[REDACTED:COOKIE]")
                else:
                    redacted_parts.append(f"{cname.strip()}={cls.redact_string(cval.strip())}")
            else:
                redacted_parts.append(cls.redact_string(part))
        return "; ".join(redacted_parts)

    @classmethod
    def redact_value(cls, data: Any) -> Any:
        """Recursively redact nested structures (dicts, lists, primitives)."""
        try:
            if isinstance(data, dict):
                cleaned_dict = {}
                for k, v in data.items():
                    k_str = str(k)
                    if cls.SENSITIVE_KEY_REGEX.match(k_str):
                        # Preserve benign nulls, booleans, and already masked values
                        if v is None:
                            cleaned_dict[k] = None
                        elif isinstance(v, bool):
                            cleaned_dict[k] = v
                        elif isinstance(v, str) and (all(c == "*" for c in v) or v.startswith("****") or v in ("[REDACTED]", "[MASKED]")):
                            cleaned_dict[k] = v
                        elif isinstance(v, str) and len(v) > 0:
                            digest = hashlib.sha256(v.encode("utf-8")).hexdigest()[:8]
                            cleaned_dict[k] = f"[REDACTED:{k_str.upper()}:{digest}]"
                        else:
                            cleaned_dict[k] = f"[REDACTED:{k_str.upper()}]"
                    else:
                        cleaned_dict[k] = cls.redact_value(v)
                return cleaned_dict
            elif isinstance(data, list):
                return [cls.redact_value(item) for item in data]
            elif isinstance(data, str):
                return cls.redact_string(data)
            else:
                return data
        except Exception as e:
            raise RedactionError(f"Value redaction failed: {e}") from e

    @classmethod
    def redact_evidence(cls, evidence: Evidence) -> Evidence:
        """Process an Evidence item through the full redaction pipeline.

        Returns a new Evidence item where all sensitive values are scrubbed.
        Guaranteed to fail closed: any exception raises RedactionError.
        """
        try:
            # Deepcopy to avoid modifying in-memory originals
            ev = copy.deepcopy(evidence)
            ev.request_headers = cls.redact_headers(ev.request_headers)
            ev.response_headers = cls.redact_headers(ev.response_headers)
            ev.request_body = cls.redact_value(ev.request_body)
            ev.response_body = cls.redact_value(ev.response_body)
            ev.observation = cls.redact_string(ev.observation)
            return ev
        except RedactionError:
            raise
        except Exception as e:
            raise RedactionError(f"Failed to redact evidence item {getattr(evidence, 'id', 'unknown')}: {e}") from e
