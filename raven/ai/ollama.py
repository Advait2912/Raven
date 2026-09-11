# Ollama client for local model integration.
# Connects from WSL to Ollama running on the host or locally.

import json
import os
import urllib.request
import urllib.error
from typing import Any, Optional


class OllamaClient:
    """Lightweight HTTP client for querying Ollama models."""

    def __init__(self, host: Optional[str] = None, model: Optional[str] = None) -> None:
        self.host = host or self._detect_host()
        self.model = model or os.environ.get("OLLAMA_MODEL", "qwen3.5:9b")

    def _detect_host(self) -> str:
        """Detect the reachable host IP for Ollama from Docker, WSL, or native host."""
        env_host = os.environ.get("OLLAMA_HOST")
        if env_host:
            return env_host

        candidates = ["host.docker.internal", "192.168.192.1", "127.0.0.1", "localhost"]
        for cand in candidates:
            url = f"http://{cand}:11434/api/tags"
            try:
                req = urllib.request.Request(url, method="GET")
                with urllib.request.urlopen(req, timeout=0.8) as resp:
                    if resp.status == 200:
                        return f"http://{cand}:11434"
            except Exception:
                continue
        return "http://127.0.0.1:11434"

    def is_available(self) -> bool:
        """Check whether the Ollama server is responding."""
        try:
            url = f"{self.host}/api/tags"
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                return resp.status == 200
        except Exception:
            return False

    def get_available_models(self) -> list[str]:
        """Fetch list of model names currently pulled in Ollama."""
        try:
            url = f"{self.host}/api/tags"
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return [m["name"] for m in data.get("models", [])]
        except Exception:
            return []

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> Optional[str]:
        """Send a prompt to Ollama and return the generated completion string."""
        url = f"{self.host}/api/generate"
        payload: dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }
        if system_prompt:
            payload["system"] = system_prompt

        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=15.0) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                return result.get("response")
        except Exception:
            return None
