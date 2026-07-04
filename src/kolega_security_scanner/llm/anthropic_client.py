"""Native Anthropic Messages-API client (direct provider; not OpenAI-compatible).

Implements the same ``LLMClient`` interface as ``LiteLLMClient`` but talks to Anthropic's
``/v1/messages`` endpoint: ``x-api-key`` + ``anthropic-version`` headers, and ``system`` as a
top-level field (not a message role). Pure stdlib urllib; never logs the key.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from kolega_security_scanner.llm.client import AgentResult
from kolega_security_scanner.llm.litellm_client import parse_json_loose

ANTHROPIC_VERSION = "2023-06-01"
DEFAULT_BASE_URL = "https://api.anthropic.com/v1"
DEFAULT_TIMEOUT = 240
DEFAULT_RETRIES = 2
DEFAULT_MAX_TOKENS = 16000


@dataclass
class AnthropicClient:
    """Anthropic Messages-API client implementing the LLMClient interface."""

    api_key: str
    model: str
    base_url: str = DEFAULT_BASE_URL
    max_tokens: int = DEFAULT_MAX_TOKENS
    timeout: int = DEFAULT_TIMEOUT
    retries: int = DEFAULT_RETRIES
    temperature: float | None = None
    call_count: int = 0
    failure_count: int = 0

    @property
    def messages_url(self) -> str:
        """The Messages endpoint."""
        return f"{self.base_url}/messages"

    def _post(self, payload: dict[str, Any]) -> tuple[int, dict[str, Any] | str]:
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": ANTHROPIC_VERSION,
            "content-type": "application/json",
        }
        req = urllib.request.Request(
            self.messages_url, data=json.dumps(payload).encode(), headers=headers, method="POST"
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

    @staticmethod
    def _split_system(messages: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
        """Anthropic takes ``system`` at the top level; lift it out of the message list."""
        system = "\n\n".join(
            str(m.get("content", "")) for m in messages if m.get("role") == "system"
        )
        convo = [m for m in messages if m.get("role") != "system"]
        return system, convo

    def chat(self, messages: list[dict[str, Any]], max_tokens: int | None = None) -> str | None:
        """Single chat completion; returns text or None on failure."""
        system, convo = self._split_system(messages)
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens or self.max_tokens,
            "messages": convo or [{"role": "user", "content": ""}],
        }
        if system:
            payload["system"] = system
        if self.temperature is not None:
            payload["temperature"] = self.temperature
        for attempt in range(self.retries + 1):
            status, data = self._post(payload)
            self.call_count += 1
            if status == 200 and isinstance(data, dict):
                blocks = data.get("content", [])
                text = "".join(b.get("text", "") for b in blocks if isinstance(b, dict))
                if text:
                    return text
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
