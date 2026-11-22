from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


class ModelError(RuntimeError):
    def __init__(self, message: str, *, response: str | None = None) -> None:
        super().__init__(message)
        self.response = response


class ModelContextError(ModelError):
    pass


class ModelOutputLimitError(ModelError):
    pass


class LocalGranite:
    model_id = "ibm-granite/granite-4.2-3b-GGUF@c40945d-Q4_K_M"

    def __init__(self, repo_root: Path, port: int = 18089, timeout_seconds: int = 120) -> None:
        key_file = repo_root / ".local" / "runtime" / "api-key.txt"
        if not key_file.is_file():
            raise ModelError("Local API key missing; run scripts/setup_local_model.ps1")
        self.api_key = key_file.read_text(encoding="ascii").strip()
        self.url = f"http://127.0.0.1:{port}/v1/chat/completions"
        self.timeout_seconds = timeout_seconds

    def complete_json(self, system: str, user: str, *, schema: dict | None = None) -> tuple[dict[str, Any], str]:
        response_format: dict[str, Any] = {"type": "json_object"}
        if schema is not None:
            response_format["schema"] = schema
        body = {
            "model": "granite-4.2-3b-Q4_K_M",
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "temperature": 0.0,
            "top_p": 1.0,
            "max_tokens": 256,
            "response_format": response_format,
            "stream": False,
        }
        request = urllib.request.Request(
            self.url,
            data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                payload = json.load(response)
        except urllib.error.HTTPError as exc:
            if exc.code == 400:
                try:
                    detail = json.loads(exc.read(16384))
                except (OSError, ValueError):
                    detail = {}
                if isinstance(detail, dict) and isinstance(error := detail.get("error"), dict):
                    if error.get("type") == "exceed_context_size_error":
                        raise ModelContextError("The local model's request exceeded its context size.") from exc
            raise ModelError(f"Local model request failed: {exc}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            if isinstance(exc, TimeoutError) or isinstance(getattr(exc, "reason", None), TimeoutError):
                raise ModelError(f"The local model did not respond within {self.timeout_seconds} seconds.") from exc
            raise ModelError(f"Local model request failed: {exc}") from exc
        try:
            choice = payload["choices"][0]
            raw = choice["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ModelError("The local model returned an invalid response.") from exc
        if not isinstance(raw, str):
            raise ModelError("The local model returned an invalid response.")
        if choice.get("finish_reason") == "length":
            raise ModelOutputLimitError("The local model response reached its output limit.", response=raw)
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ModelError("The local model returned invalid JSON.", response=raw) from exc
        if not isinstance(parsed, dict):
            raise ModelError("The local model response was not a JSON object.", response=raw)
        return parsed, raw
