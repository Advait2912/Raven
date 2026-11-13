# Tests for NetworkGateway SSRF defense, DNS rebinding, and safe egress execution.

import http.server
import socket
import threading
import pytest
from raven.core.network import NetworkGateway, NetworkGatewayError
from raven.core.policy import Scope


@pytest.mark.parametrize(
    "ip",
    [
        "10.0.0.1",
        "10.254.254.254",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "192.168.100.50",
        "169.254.169.254",  # AWS/GCP/Azure Metadata
        "169.254.1.1",
        "0.0.0.0",
        "224.0.0.1",        # Multicast
        "240.0.0.1",        # Reserved
        "fc00::1",          # IPv6 Unique Local
        "fe80::1",          # IPv6 Link Local
    ],
)
def test_network_gateway_blocks_private_and_metadata_ips(ip):
    gw = NetworkGateway()
    allowed, reason = gw.check_ip_allowed(ip, allow_loopback=False)
    assert allowed is False
    assert "blocked" in reason.lower() or "private" in reason.lower()


def test_network_gateway_loopback_handling():
    gw = NetworkGateway()

    # Allowed when allow_loopback=True (lab mode)
    allowed, _ = gw.check_ip_allowed("127.0.0.1", allow_loopback=True)
    assert allowed is True

    # Blocked when allow_loopback=False (strict pentesting mode)
    blocked, reason = gw.check_ip_allowed("127.0.0.1", allow_loopback=False)
    assert blocked is False
    assert "loopback" in reason.lower()


def test_network_gateway_blocks_cloud_metadata_hostname():
    gw = NetworkGateway()
    with pytest.raises(NetworkGatewayError, match="blocked cloud metadata"):
        gw.resolve_hostname("metadata.google.internal")


def test_network_gateway_enforces_allowed_methods():
    scope = Scope(
        allowed_domains=["localhost", "127.0.0.1"],
        allowed_paths=["/api/test"],
        allowed_methods=["GET", "POST"],
        allow_loopback=True,
    )
    gw = NetworkGateway(scope=scope)

    # DELETE is not in allowed_methods
    with pytest.raises(NetworkGatewayError, match="not allowed by scope"):
        gw.execute_request("DELETE", "http://127.0.0.1/api/test")

    # Violation is recorded
    assert len(gw.violations) >= 1
    assert gw.violations[-1].violation_type == "METHOD_NOT_ALLOWED"


def test_network_gateway_redirect_and_pinning_against_local_server():
    """Spin up a tiny local HTTP server that issues a redirect and verify safe traversal."""

    class RedirectHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/api/orders/final")
                self.end_headers()
            elif self.path == "/api/orders/final":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status": "ok", "delivered": true}')
            elif self.path == "/evil-redirect":
                self.send_response(302)
                self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
                self.end_headers()
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), RedirectHandler)
    port = server.server_port
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        # Case 1: Permitted redirect within scope
        scope = Scope(
            allowed_domains=["127.0.0.1", "localhost"],
            allowed_paths=["/redirect", "/api/orders/"],
            allowed_methods=["GET"],
            allow_loopback=True,
        )
        gw = NetworkGateway(scope=scope)

        resp = gw.execute_request("GET", f"http://127.0.0.1:{port}/redirect")
        assert resp.status_code == 200
        assert "delivered" in resp.body
        assert resp.resolved_ip == "127.0.0.1"

        # Case 2: Redirect targeting cloud metadata or blocked path
        scope_with_evil_start = Scope(
            allowed_domains=["127.0.0.1"],
            allowed_paths=["/evil-redirect", "/latest/"],
            allow_loopback=True,
        )
        gw_evil = NetworkGateway(scope=scope_with_evil_start)

        with pytest.raises(NetworkGatewayError):
            gw_evil.execute_request("GET", f"http://127.0.0.1:{port}/evil-redirect")

        assert len(gw_evil.violations) >= 1

    finally:
        server.shutdown()
        server.server_close()
