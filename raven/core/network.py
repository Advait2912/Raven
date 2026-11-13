# NetworkGateway for RAVEN.
# Design choice: Zero external dependencies (stdlib socket, ipaddress, http.client).
# Dual-layer scope enforcement: Deterministic SSRF and DNS rebinding prevention.
# A target cannot bypass scope via DNS rebinding or malicious HTTP redirects.

import http.client
import ipaddress
import socket
import ssl
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Optional, Tuple
from .models import ScopeViolation
from .policy import PolicyGate, Scope


class NetworkGatewayError(Exception):
    """Raised when an outbound network request violates network boundaries."""
    pass


@dataclass
class NetworkResponse:
    """Safe response returned by NetworkGateway HTTP execution."""
    status_code: int
    headers: dict[str, str]
    body: str
    resolved_ip: str
    final_url: str


class NetworkGateway:
    """Deterministic network egress gate.

    Enforces private IP blocking, DNS rebinding prevention,
    and safe redirect validation.
    """

    # Blocked CIDR ranges (SSRF defense)
    BLOCKED_NETWORKS = [
        # RFC 1918 Private IPv4
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        # Link-local & Cloud Metadata (AWS, Azure, GCP, OpenStack)
        ipaddress.ip_network("169.254.0.0/16"),
        # Current network & Multicast / Reserved
        ipaddress.ip_network("0.0.0.0/8"),
        ipaddress.ip_network("224.0.0.0/4"),
        ipaddress.ip_network("240.0.0.0/4"),
        # IPv6 Private / Link-local / Unique Local
        ipaddress.ip_network("fc00::/7"),
        ipaddress.ip_network("fe80::/10"),
    ]

    LOOPBACK_NETWORKS = [
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("::1/128"),
    ]

    BLOCKED_HOSTNAMES = {
        "metadata.google.internal",
        "instance-data",
    }

    def __init__(self, scope: Optional[Scope] = None) -> None:
        self.scope = scope or Scope()
        self.policy_gate = PolicyGate(self.scope)
        self.violations: list[ScopeViolation] = []

    def check_ip_allowed(self, ip_str: str, allow_loopback: bool = True) -> Tuple[bool, str]:
        """Check if an IP address is permitted or blocked by SSRF rules."""
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, f"Invalid IP address format: {ip_str}"

        # Loopback check
        is_loopback = any(ip in net for net in self.LOOPBACK_NETWORKS)
        if is_loopback:
            if allow_loopback:
                return True, "Loopback allowed by scope configuration."
            return False, f"Loopback address '{ip_str}' is blocked in non-local assessment mode."

        # Blocked ranges check
        for net in self.BLOCKED_NETWORKS:
            if ip in net:
                return False, f"IP address '{ip_str}' falls within blocked private/reserved range {net}."

        return True, "IP is valid and in public range."

    def resolve_hostname(self, hostname: str, port: int = 80) -> list[str]:
        """Resolve a hostname to IP addresses once per request (defeats DNS caching bugs)."""
        if hostname.lower() in self.BLOCKED_HOSTNAMES:
            raise NetworkGatewayError(f"Target hostname '{hostname}' is an explicitly blocked cloud metadata name.")

        try:
            # Query getaddrinfo
            addr_info = socket.getaddrinfo(hostname, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
            resolved_ips = list({info[4][0] for info in addr_info})
            if not resolved_ips:
                raise NetworkGatewayError(f"DNS resolution returned no records for host '{hostname}'.")
            return resolved_ips
        except socket.gaierror as e:
            raise NetworkGatewayError(f"DNS resolution failed for '{hostname}': {e}") from e

    def validate_target(self, url: str) -> Tuple[str, str, int]:
        """Validate URL against PolicyGate and resolve+validate IP through NetworkGateway.

        Returns (canonical_hostname, validated_ip, port).
        Raises NetworkGatewayError if any check fails.
        """
        parsed = urllib.parse.urlparse(url)
        if not parsed.scheme or parsed.scheme.lower() not in ("http", "https"):
            err = f"Unsupported URL scheme '{parsed.scheme}'. Only http and https are allowed."
            self._record_violation("UNSUPPORTED_SCHEME", url, err)
            raise NetworkGatewayError(err)

        hostname = parsed.hostname
        if not hostname:
            err = f"Invalid target URL without hostname: {url}"
            self._record_violation("INVALID_URL", url, err)
            raise NetworkGatewayError(err)

        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)

        # 1. PolicyGate check (domain & path scope)
        decision = self.policy_gate.evaluate(
            action_id="network_egress",
            target_path=parsed.path or "/",
            target_domain=hostname,
            prerequisites=[],
            satisfied_prerequisites=[],
        )
        if not decision.allowed:
            self._record_violation("POLICY_REJECTED", url, decision.reason)
            raise NetworkGatewayError(f"PolicyGate rejected request to {url}: {decision.reason}")

        # 2. DNS Resolution & SSRF check
        resolved_ips = self.resolve_hostname(hostname, port)
        for ip in resolved_ips:
            allowed, reason = self.check_ip_allowed(ip, allow_loopback=self.scope.allow_loopback)
            if not allowed:
                self._record_violation("PRIVATE_IP", f"{url} ({ip})", reason)
                raise NetworkGatewayError(f"NetworkGateway blocked {url}: {reason}")

        # Choose the first validated IP
        return hostname, resolved_ips[0], port

    def execute_request(
        self,
        method: str,
        url: str,
        headers: Optional[dict[str, str]] = None,
        body: Optional[Any] = None,
        timeout: float = 10.0,
        max_redirects: int = 5,
        max_body_bytes: int = 1_048_576,
    ) -> NetworkResponse:
        """Execute HTTP request directly against the validated IP to defeat DNS rebinding.

        Follows redirects with full re-validation at every hop. Response body is bounded
        by max_body_bytes (default 1MB).
        """
        method_upper = method.upper().strip()
        if method_upper not in [m.upper() for m in self.scope.allowed_methods]:
            err = f"HTTP method '{method_upper}' not allowed by scope."
            self._record_violation("METHOD_NOT_ALLOWED", url, err)
            raise NetworkGatewayError(err)

        current_url = url
        redirects_followed = 0

        while True:
            parsed = urllib.parse.urlparse(current_url)
            scheme = parsed.scheme.lower()
            hostname, validated_ip, port = self.validate_target(current_url)

            # Construct safe headers
            req_headers = dict(headers or {})
            req_headers["Host"] = hostname if (port in (80, 443)) else f"{hostname}:{port}"
            req_headers.setdefault("User-Agent", "RAVEN-Security-Engine/1.0")

            req_path = parsed.path or "/"
            if parsed.query:
                req_path += f"?{parsed.query}"

            body_bytes = None
            if body is not None:
                if isinstance(body, bytes):
                    body_bytes = body
                elif isinstance(body, str):
                    body_bytes = body.encode("utf-8")
                else:
                    import json
                    body_bytes = json.dumps(body).encode("utf-8")
                    req_headers.setdefault("Content-Type", "application/json")

            # Pinning connection to validated_ip prevents DNS rebinding TOCTOU attacks
            try:
                if scheme == "https":
                    context = ssl.create_default_context()
                    conn = http.client.HTTPSConnection(
                        host=validated_ip,
                        port=port,
                        timeout=timeout,
                        context=context,
                    )
                else:
                    conn = http.client.HTTPConnection(
                        host=validated_ip,
                        port=port,
                        timeout=timeout,
                    )

                conn.request(method=method_upper, url=req_path, body=body_bytes, headers=req_headers)
                resp = conn.getresponse()
                resp_status = resp.status
                resp_headers = {k.lower(): v for k, v in resp.getheaders()}
                resp_body_bytes = resp.read(max_body_bytes)
                conn.close()

                resp_body_text = resp_body_bytes.decode("utf-8", errors="replace")

            except Exception as e:
                raise NetworkGatewayError(f"HTTP transport failed connecting to {validated_ip}:{port} for {current_url}: {e}") from e

            # Check for redirect (301, 302, 303, 307, 308)
            if resp_status in (301, 302, 303, 307, 308) and "location" in resp_headers:
                redirects_followed += 1
                if redirects_followed > max_redirects:
                    err = f"Maximum redirect limit ({max_redirects}) exceeded."
                    self._record_violation("MAX_REDIRECTS_EXCEEDED", current_url, err)
                    raise NetworkGatewayError(err)

                location = resp_headers["location"]
                next_url = urllib.parse.urljoin(current_url, location)

                # Method adjustment on 303 or 302/301 for non-GET
                if resp_status == 303 or (resp_status in (301, 302) and method_upper != "GET"):
                    method_upper = "GET"
                    body_bytes = None

                current_url = next_url
                continue

            return NetworkResponse(
                status_code=resp_status,
                headers=resp_headers,
                body=resp_body_text,
                resolved_ip=validated_ip,
                final_url=current_url,
            )

    def _record_violation(self, violation_type: str, target: str, reason: str) -> None:
        import uuid
        violation = ScopeViolation(
            id=f"VIO-{uuid.uuid4().hex[:8].upper()}",
            violation_type=violation_type,
            attempted_target=target,
            blocked_by="NetworkGateway",
            details=reason,
        )
        self.violations.append(violation)
