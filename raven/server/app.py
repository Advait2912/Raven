# HTTP Server dispatching REST API and serving Web UI.
# Runs with standard library Python—zero heavy dependencies needed.

import json
import mimetypes
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
from raven.server.routes import DemoController

controller = DemoController()


class RavenRequestHandler(BaseHTTPRequestHandler):
    """Handles HTTP requests for RAVEN dashboard and demo API."""

    def _set_cors_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self._set_cors_headers()
        self.end_headers()

    def _send_json(self, data: dict, status: int = 200) -> None:
        raw = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self._set_cors_headers()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _send_text(self, text: str, content_type: str = "text/plain", status: int = 200) -> None:
        raw = text.encode("utf-8")
        self.send_response(status)
        self._set_cors_headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _read_json_body(self) -> dict:
        content_len = int(self.headers.get("Content-Length", 0))
        if content_len > 0:
            body = self.rfile.read(content_len).decode("utf-8")
            try:
                return json.loads(body)
            except Exception:
                return {}
        return {}

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/api/health":
            self._send_json({"status": "online", "service": "raven", "version": "1.0.0"})
            return

        if path == "/api/demo/mode":
            self._send_json({"mode": controller.mode})
            return

        if path == "/api/demo/models":
            models = controller.tutor.ollama.get_available_models()
            curr = controller.tutor.ollama.model
            self._send_json({"current_model": curr, "available_models": models})
            return

        if path == "/api/demo/evidence":
            items = [e.to_dict() for e in controller.evidence_store.get_all_evidence()]
            self._send_json({"evidence": items})
            return

        if path == "/api/demo/findings":
            items = [f.to_dict() for f in controller.evidence_store.get_all_findings()]
            self._send_json({"findings": items})
            return

        if path == "/api/demo/hints":
            lvl = int(query.get("level", [1])[0])
            self._send_json(controller.tutor.get_progressive_hint(lvl))
            return

        if path == "/api/demo/student/hint":
            tier = int(query.get("tier", [1])[0])
            sess = query.get("session_id", ["default"])[0]
            hint = controller.tutor.request_student_hint(tier=tier, session_id=sess, evidence_list=controller.evidence_store.get_all_evidence())
            self._send_json({
                "tier": hint.tier,
                "tier_name": hint.tier_name,
                "title": hint.title,
                "content": hint.content,
                "unlocked": hint.unlocked,
                "cooldown_remaining": hint.cooldown_remaining,
                "message": hint.message,
            })
            return

        if path == "/api/demo/explain":
            findings = controller.evidence_store.get_all_findings()
            all_ev = controller.evidence_store.get_all_evidence()
            if not findings:
                self._send_json({"explanation": "No confirmed findings recorded yet. Run an assessment module first."})
                return
            self._send_json(controller.tutor.explain_finding(findings[0], all_ev))
            return

        if path == "/api/demo/remediation":
            self._send_json(controller.tutor.get_remediation_diff())
            return

        if path == "/api/demo/report":
            fmt = query.get("format", ["json"])[0]
            rep = controller.generate_report(fmt)
            if fmt.lower() == "markdown":
                self._send_text(str(rep), content_type="text/markdown; charset=utf-8")
            else:
                self._send_json(rep)
            return

        # Serve static web frontend
        self._serve_static(path)

    def do_POST(self) -> None:
        path = urlparse(self.path).path

        if path == "/api/demo/run":
            res = controller.run_full()
            self._send_json(res)
            return

        if path == "/api/demo/modules/run":
            body = self._read_json_body()
            module_name = body.get("module", "all")
            res = controller.run_module(module_name)
            self._send_json(res)
            return

        if path == "/api/demo/mode":
            body = self._read_json_body()
            mode = body.get("mode", "student")
            res = controller.set_mode(mode)
            self._send_json(res)
            return

        if path == "/api/demo/step":
            body = self._read_json_body()
            step = int(body.get("step", 1))
            res = controller.run_step(step)
            self._send_json(res)
            return

        if path == "/api/demo/reset":
            res = controller.reset()
            self._send_json(res)
            return

        if path == "/api/demo/patch":
            body = self._read_json_body()
            vuln = bool(body.get("is_vulnerable", True))
            res = controller.toggle_patch(vuln)
            self._send_json(res)
            return

        if path == "/api/demo/model":
            body = self._read_json_body()
            new_model = body.get("model")
            if new_model:
                controller.tutor.ollama.model = new_model
            self._send_json({"status": "UPDATED", "current_model": controller.tutor.ollama.model})
            return

        self._send_json({"error": f"Endpoint '{path}' not found"}, 404)

    def _serve_static(self, path: str) -> None:
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../web"))
        clean_path = path.lstrip("/")
        if not clean_path or clean_path == "":
            clean_path = "index.html"

        file_path = os.path.join(base_dir, clean_path)
        if not os.path.isfile(file_path):
            self.send_error(404, f"File {clean_path} not found")
            return

        mime_type, _ = mimetypes.guess_type(file_path)
        mime_type = mime_type or "application/octet-stream"

        try:
            with open(file_path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", mime_type)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            self.send_error(500, f"Error reading file: {e}")


def run_server(port: int = 8000, host: str = "0.0.0.0") -> None:
    server_address = (host, port)
    httpd = ThreadingHTTPServer(server_address, RavenRequestHandler)
    print(f"[*] RAVEN Dashboard running at http://{host}:{port}/")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")
    finally:
        httpd.server_close()
