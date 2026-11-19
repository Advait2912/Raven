# Vulnerable Lab Target.
# Mode B Learning Application Lab implementing multi-vector vulnerability scenarios:
# 1. IDOR (Missing object-level authorization on GET /api/orders/{id})
# 2. Insecure Security Headers & Cookie Flags (GET /)
# 3. Information Disclosure (Exposed /.env, /.git/HEAD)
# 4. Technology Stack Fingerprint Disclosures (GET /)
# 5. Permissive CORS Misconfiguration (GET /api/user/profile)
# 6. Excessive Sensitive Data Exposure (GET /api/user/profile)

import re
from typing import Any
from .base import BaseTarget, TargetRequest, TargetResponse
from .database import LabDatabase


class VulnerableLabTarget(BaseTarget):
    """Controlled intentionally vulnerable target service for RAVEN assessments."""
    id = "target_finbank_orders"
    name = "FinBank Order & Account API"
    base_url = "http://localhost:8000"

    def __init__(self) -> None:
        self.db = LabDatabase()
        self.is_vulnerable = True

    def reset_state(self) -> None:
        self.db.reset()
        self.is_vulnerable = True

    def handle_request(self, req: TargetRequest) -> TargetResponse:
        method = req.method.upper()
        path = req.path
        origin = req.headers.get("Origin", "")

        # 1. Health check
        if path == "/api/health" and method == "GET":
            return TargetResponse(
                status_code=200,
                headers={"Content-Type": "application/json"},
                body={"status": "online", "target": self.name, "vulnerable": self.is_vulnerable},
            )

        # 2. Root service endpoint (Headers & Fingerprint test)
        if path in ("/", "/index.html") and method in ("GET", "HEAD"):
            if self.is_vulnerable:
                return TargetResponse(
                    status_code=200,
                    headers={
                        "Content-Type": "text/html; charset=utf-8",
                        "Server": "nginx/1.24.0",
                        "X-Powered-By": "Express",
                        "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'",
                        "Set-Cookie": "session_id=secret_sess_abc123; Path=/",
                    },
                    body=(
                        "<!DOCTYPE html><html><head>"
                        "<meta name=\"generator\" content=\"WordPress 6.4.2\" />"
                        "<title>FinBank Portal</title></head><body>"
                        "<div id=\"root\" data-reactroot=\"\"><h1>FinBank Corporate Portal</h1></div>"
                        "</body></html>"
                    ),
                )
            else:
                return TargetResponse(
                    status_code=200,
                    headers={
                        "Content-Type": "text/html; charset=utf-8",
                        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                        "X-Frame-Options": "DENY",
                        "X-Content-Type-Options": "nosniff",
                        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; object-src 'none'",
                        "Referrer-Policy": "strict-origin-when-cross-origin",
                        "Set-Cookie": "session_id=secret_sess_abc123; Path=/; Secure; HttpOnly; SameSite=Strict",
                    },
                    body=(
                        "<!DOCTYPE html><html><head>"
                        "<title>FinBank Portal</title></head><body>"
                        "<div id=\"app\"><h1>FinBank Corporate Portal</h1></div>"
                        "</body></html>"
                    ),
                )

        # 3. Information disclosure probing: /.env, /.git/HEAD
        if path in ("/.env", "/.env.local") and method in ("GET", "HEAD"):
            if self.is_vulnerable:
                return TargetResponse(
                    status_code=200,
                    headers={"Content-Type": "text/plain"},
                    body="DB_USER=postgres\nDB_PASSWORD=finbank_secret_pass_123!\nAPI_SECRET=sk_live_finbank_999\n",
                )
            return TargetResponse(404, {"Content-Type": "application/json"}, {"error": "Not Found", "path": path})

        if path in ("/.git/HEAD", "/.git/config") and method in ("GET", "HEAD"):
            if self.is_vulnerable:
                return TargetResponse(
                    status_code=200,
                    headers={"Content-Type": "text/plain"},
                    body="ref: refs/heads/main\n",
                )
            return TargetResponse(404, {"Content-Type": "application/json"}, {"error": "Not Found", "path": path})

        # 4. User profile endpoint (CORS & Excessive Data Exposure test)
        if path == "/api/user/profile" and method in ("GET", "OPTIONS"):
            if self.is_vulnerable:
                headers = {
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": origin if origin else "http://localhost:8000",
                    "Access-Control-Allow-Credentials": "true",
                    "Access-Control-Allow-Methods": "GET, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type, Authorization",
                }
                body = {
                    "id": 42,
                    "username": "admin",
                    "email": "admin@finbank.local",
                    "role": "financial_officer",
                    "password_hash": "$2b$12$e8Yx9T7G1b5v.super_secret_hash_value_do_not_leak",
                    "password_reset_token": "tok_rst_finbank_998877",
                    "api_key": "sk_live_finbank_master_key_999",
                    "social_security_number": "000-12-3456",
                }
                return TargetResponse(status_code=200, headers=headers, body=body)
            else:
                headers = {
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": "http://localhost:8000",
                    "Access-Control-Allow-Credentials": "false",
                    "Access-Control-Allow-Methods": "GET, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type, Authorization",
                }
                body = {
                    "id": 42,
                    "username": "admin",
                    "email": "admin@finbank.local",
                    "role": "financial_officer",
                }
                return TargetResponse(status_code=200, headers=headers, body=body)

        # 5. Authentication Login
        if path == "/api/auth/login" and method == "POST":
            return self._handle_login(req.body)

        # 6. Order details by ID: GET /api/orders/{id}
        order_match = re.match(r"^/api/orders/(\w+)$", path)
        if order_match and method == "GET":
            order_id = order_match.group(1)
            return self._handle_get_order(req, order_id)

        # 7. Fallback 404
        return TargetResponse(
            status_code=404,
            headers={"Content-Type": "application/json"},
            body={"error": "Not Found", "path": path},
        )

    def _handle_login(self, body: Any) -> TargetResponse:
        if not isinstance(body, dict):
            return TargetResponse(400, {"Content-Type": "application/json"}, {"error": "Invalid JSON body"})

        username = body.get("username")
        password = body.get("password")

        for user in self.db.users.values():
            if user.username == username and user.password == password:
                return TargetResponse(
                    status_code=200,
                    headers={"Content-Type": "application/json"},
                    body={
                        "message": "Authentication successful",
                        "user_id": user.id,
                        "username": user.username,
                        "token": user.token,
                    },
                )

        return TargetResponse(
            status_code=401,
            headers={"Content-Type": "application/json"},
            body={"error": "Invalid username or password"},
        )

    def _handle_get_order(self, req: TargetRequest, order_id: str) -> TargetResponse:
        # Check authentication token
        auth_header = req.headers.get("Authorization", "")
        token = auth_header.replace("Bearer ", "").strip()
        user = self.db.get_user_by_token(token)

        if not user:
            return TargetResponse(
                status_code=401,
                headers={"Content-Type": "application/json"},
                body={"error": "Unauthorized. Missing or invalid Bearer token."},
            )

        order = self.db.get_order(order_id)
        if not order:
            return TargetResponse(
                status_code=404,
                headers={"Content-Type": "application/json"},
                body={"error": f"Order {order_id} not found."},
            )

        # IDOR VULNERABILITY CHECK:
        # If patched (not vulnerable), enforce authorization check:
        if not self.is_vulnerable and order.owner_id != user.id:
            return TargetResponse(
                status_code=403,
                headers={"Content-Type": "application/json"},
                body={"error": "Forbidden: You do not have permission to view this order."},
            )

        # Vulnerable behavior: Returns the resource regardless of user ownership
        return TargetResponse(
            status_code=200,
            headers={"Content-Type": "application/json"},
            body={
                "order_id": order.id,
                "owner_id": order.owner_id,
                "item": order.item,
                "amount": order.amount,
                "shipping_address": order.shipping_address,
            },
        )
