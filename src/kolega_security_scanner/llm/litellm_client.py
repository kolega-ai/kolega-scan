"""OpenAI-compatible LLM client (pure stdlib ``urllib``, no vendor SDK).

Used for both the direct-provider backends (DeepSeek/Moonshot/OpenAI) and the
LiteLLM proxy backend. Reads config from the environment (API key + base URL);
never logs the key.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from kolega_security_scanner.llm._model_registry import DEFAULT_MODEL
from kolega_security_scanner.llm.client import AgentResult

DEFAULT_BASE_URL = "http://localhost:4100/v1"
DEFAULT_TIMEOUT = 240
DEFAULT_RETRIES = 2
DEFAULT_MAX_TOKENS = 16000

_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)


def parse_json_loose(text: str) -> dict[str, Any] | list[Any] | None:
    """Parse JSON from possibly-fenced / chatty model output."""
    if not text:
        return None
    stripped = _FENCE_RE.sub("", text).strip()
    try:
        return json.loads(stripped)  # type: ignore[no-any-return]
    except json.JSONDecodeError:
        pass
    for opener, closer in (("{", "}"), ("[", "]")):
        start, end = stripped.find(opener), stripped.rfind(closer)
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(stripped[start : end + 1])  # type: ignore[no-any-return]
            except json.JSONDecodeError:
                continue
    return None


@dataclass
class LiteLLMClient:
    """OpenAI-compatible LiteLLM client implementing the LLMClient interface."""

    api_key: str
    model: str
    base_url: str = DEFAULT_BASE_URL
    max_tokens: int = DEFAULT_MAX_TOKENS
    timeout: int = DEFAULT_TIMEOUT
    retries: int = DEFAULT_RETRIES
    temperature: float | None = None
    call_count: int = 0
    failure_count: int = 0

    @classmethod
    def from_env(cls, model: str = DEFAULT_MODEL, **overrides: Any) -> LiteLLMClient:
        """Build the LiteLLM-proxy client from env: LITELLM_API_KEY + LITELLM_BASE_URL/LITELLM_URL.

        The ``provider/model`` spec is passed through verbatim for the proxy to route.
        """
        from kolega_security_scanner.cli._errors import LLMConfigError

        key = os.environ.get("LITELLM_API_KEY", "").strip()
        if not key:
            raise LLMConfigError("LITELLM_API_KEY is not set")
        base = (
            os.environ.get("LITELLM_BASE_URL") or os.environ.get("LITELLM_URL") or DEFAULT_BASE_URL
        ).rstrip("/")
        return cls(api_key=key, model=model, base_url=base, **overrides)

    @property
    def chat_url(self) -> str:
        """The chat-completions endpoint."""
        return f"{self.base_url}/chat/completions"

    def _post(self, payload: dict[str, Any]) -> tuple[int, dict[str, Any] | str]:
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        req = urllib.request.Request(
            self.chat_url, data=json.dumps(payload).encode(), headers=headers, method="POST"
        )
        try:
            resp = urllib.request.urlopen(req, timeout=self.timeout)  # noqa: S310
            raw = resp.read().decode("utf-8", "replace")
            try:
                return int(resp.status), json.loads(raw)
            except json.JSONDecodeError:
                return int(resp.status), raw
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")
        except Exception as e:  # noqa: BLE001 - never leak key; report transport failure
            return 0, f"transport-error: {type(e).__name__}"

    def chat(self, messages: list[dict[str, Any]], max_tokens: int | None = None) -> str | None:
        """Single chat completion; returns content text or None on failure."""
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens or self.max_tokens,
        }
        if self.temperature is not None:
            payload["temperature"] = self.temperature
        for attempt in range(self.retries + 1):
            status, data = self._post(payload)
            self.call_count += 1
            if status == 200 and isinstance(data, dict):
                content = data.get("choices", [{}])[0].get("message", {}).get("content", "") or ""
                if content:
                    return str(content)
            if attempt < self.retries:
                time.sleep(1.5 * (attempt + 1))
        self.failure_count += 1
        return None

    def chat_json(
        self, messages: list[dict[str, Any]], schema_hint: str = "", max_tokens: int | None = None
    ) -> dict[str, Any] | list[Any] | None:
        """Chat then parse JSON loosely. ``schema_hint`` kept for API symmetry."""
        del schema_hint
        text = self.chat(messages, max_tokens=max_tokens)
        return parse_json_loose(text) if text is not None else None

    def preflight(self) -> bool:
        """Cheap reachability check (expects a 'pong')."""
        text = self.chat(
            [{"role": "user", "content": "Reply with exactly: pong"}],
            max_tokens=min(self.max_tokens, 8000),
        )
        return bool(text and "pong" in text.lower())

    def complete(self, prompt: str, **opts: Any) -> str:
        """Single-shot completion (maps to chat)."""
        return self.chat([{"role": "user", "content": prompt}]) or ""

    def run_agent(self, system: str, messages: list[Any], tools: list[Any]) -> AgentResult:
        """Minimal agentic run (single turn; tool-loop is future work)."""
        del tools
        msgs = [{"role": "system", "content": system}, *messages]
        return AgentResult(output=self.chat(msgs) or "")
