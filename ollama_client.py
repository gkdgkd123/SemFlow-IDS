from __future__ import annotations

import json
from typing import Any
from urllib import request


class OllamaClient:
    def __init__(self, base_url: str = "http://127.0.0.1:11434", model: str = "qwen2.5:3b"):
        self.base_url = base_url.rstrip("/")
        self.model = model

    def generate(self, prompt: str) -> dict[str, Any]:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }
        req = request.Request(
            url=f"{self.base_url}/api/generate",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with request.urlopen(req, timeout=60) as resp:
            body = resp.read().decode("utf-8")
            return json.loads(body)


def analyze_l1(sample: dict[str, Any], client: OllamaClient | None = None) -> dict[str, Any]:
    return {
        "stage": "L1",
        "label": "suspicious",
        "reason": "L1 placeholder; not enabled in milestone-1",
        "input_sample_id": sample.get("sample_id"),
    }


def analyze_l2(sample: dict[str, Any], client: OllamaClient | None = None) -> dict[str, Any]:
    return {
        "stage": "L2",
        "label": "suspicious",
        "reason": "L2 placeholder; not enabled in milestone-1",
        "input_sample_id": sample.get("sample_id"),
    }
