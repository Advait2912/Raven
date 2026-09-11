# In-memory database for the vulnerable lab target.
# Provides seed data with ground truth ownership for deterministic validation.

from dataclasses import dataclass
from typing import Optional


@dataclass
class UserRecord:
    id: str
    username: str
    password: str
    token: str
    role: str


@dataclass
class OrderRecord:
    id: str
    owner_id: str
    item: str
    amount: float
    shipping_address: str


class LabDatabase:
    """In-memory database holding users, sessions, and orders."""

    def __init__(self) -> None:
        self.users: dict[str, UserRecord] = {}
        self.tokens: dict[str, str] = {}  # token -> user_id
        self.orders: dict[str, OrderRecord] = {}
        self.reset()

    def reset(self) -> None:
        self.users = {
            "usr_alice": UserRecord(
                id="usr_alice",
                username="alice",
                password="alicepassword123",
                token="tok_alice_session_8819",
                role="customer",
            ),
            "usr_bob": UserRecord(
                id="usr_bob",
                username="bob",
                password="bobpassword456",
                token="tok_bob_session_9921",
                role="customer",
            ),
        }
        self.tokens = {
            "tok_alice_session_8819": "usr_alice",
            "tok_bob_session_9921": "usr_bob",
        }
        self.orders = {
            "101": OrderRecord(
                id="101",
                owner_id="usr_alice",
                item="Quantum Mechanical Keyboard",
                amount=149.99,
                shipping_address="42 Elm Street, Seattle, WA",
            ),
            "102": OrderRecord(
                id="102",
                owner_id="usr_bob",
                item="Confidential Security Hardened Router",
                amount=899.50,
                shipping_address="777 Vault Road, Austin, TX",
            ),
        }

    def get_user_by_token(self, token: str) -> Optional[UserRecord]:
        user_id = self.tokens.get(token)
        return self.users.get(user_id) if user_id else None

    def get_order(self, order_id: str) -> Optional[OrderRecord]:
        return self.orders.get(order_id)
