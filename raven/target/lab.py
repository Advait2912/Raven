# Vulnerable Lab Target.
# Mode B Learning Application Lab implementing an IDOR vulnerability.
# Missing object-level authorization on GET /api/orders/{id}.

import re
from typing import Any
from .base import BaseTarget, TargetRequest, TargetResponse
from .database import LabDatabase


class VulnerableLabTarget(BaseTarget):
    """Controlled intentionally vulnerable target service."""
    id = "target_finbank_orders"
    name = "FinBank Order Management API"
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

        # 1. Health check
        if path == "/api/health" and method == "GET":
            return TargetResponse(
                status_code=200,
                headers={"Content-Type": "application/json"},
                body={"status": "online", "target": self.name, "vulnerable": self.is_vulnerable},
            )

        # 2. Authentication Login
        if path == "/api/auth/login" and method == "POST":
            return self._handle_login(req.body)

        # 3. Order details by ID: GET /api/orders/{id}
        order_match = re.match(r"^/api/orders/(\w+)$", path)
        if order_match and method == "GET":
            order_id = order_match.group(1)
            return self._handle_get_order(req, order_id)

        # 4. Fallback 404
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
