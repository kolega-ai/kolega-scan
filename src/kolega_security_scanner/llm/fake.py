"""Offline fake LLM client for tests and dry runs (zero network)."""

from __future__ import annotations

from typing import Any

from kolega_security_scanner.llm.client import AgentResult


class FakeLLMClient:
    """Returns canned responses deterministically; makes no network call."""

    def __init__(self, responses: list[str] | None = None) -> None:
        """Store canned responses to return in order."""
        self._responses = list(responses or [])
        self._i = 0

    def complete(self, prompt: str, **opts: Any) -> str:
        """Return the next canned response (or echo the prompt if exhausted)."""
        if self._i < len(self._responses):
            out = self._responses[self._i]
            self._i += 1
            return out
        return ""

    def run_agent(self, system: str, messages: list[Any], tools: list[Any]) -> AgentResult:
        """Return a canned agent result."""
        return AgentResult(output=self.complete(system))

    def chat(self, messages: list[Any], max_tokens: int | None = None) -> str | None:
        """Return the next canned response."""
        return self.complete("")

    def chat_json(
        self, messages: list[Any], schema_hint: str = "", max_tokens: int | None = None
    ) -> dict[str, Any] | list[Any] | None:
        """Return the next canned response parsed as JSON (or None)."""
        import json

        text = self.complete("")
        if not text:
            return None
        try:
            return json.loads(text)  # type: ignore[no-any-return]
        except json.JSONDecodeError:
            return None

    def preflight(self) -> bool:
        """Always reachable (offline fake)."""
        return True
