"""LLM client interface (single-shot + agentic) and the real-client factory.

The real client is constructed lazily and only when an LLM is needed; the API key is
read from the environment and validated then. Output is not made deterministic (FR-017).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True)
class AgentResult:
    """Result of an agentic (multi-turn/tool-using) LLM run."""

    output: str
    steps: tuple[Any, ...] = field(default_factory=tuple)


@runtime_checkable
class LLMClient(Protocol):
    """Injectable LLM interface. Real in production, fake in tests."""

    def complete(self, prompt: str, **opts: Any) -> str:
        """Single-shot completion."""
        ...

    def run_agent(self, system: str, messages: list[Any], tools: list[Any]) -> AgentResult:
        """Run one completion and wrap it as an ``AgentResult``.

        The bundled OpenAI-compatible and Anthropic clients implement this as a single
        turn; ``tools`` is accepted for interface compatibility but not yet exercised
        (``AgentResult.steps`` is empty). Tool-using multi-turn loops may be added later.
        """
        ...

    def chat(self, messages: list[Any], max_tokens: int | None = None) -> str | None:
        """Single chat completion; content text or None on failure."""
        ...

    def chat_json(
        self, messages: list[Any], schema_hint: str = "", max_tokens: int | None = None
    ) -> dict[str, Any] | list[Any] | None:
        """Chat then parse JSON loosely."""
        ...

    def preflight(self) -> bool:
        """Cheap reachability check; True if the model is reachable."""
        ...


# Only these keys are ever read from a local .env — a scanned repo may be
# untrusted, so we never let its .env inject arbitrary vars (PATH, LD_PRELOAD,
# …) into the process or any subprocess we spawn.
_DOTENV_ALLOWED_KEYS = frozenset(
    {
        "DEEPSEEK_API_KEY",
        "MOONSHOT_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "LITELLM_API_KEY",
        "LITELLM_URL",
        "LITELLM_BASE_URL",
        "KOLEGA_LLM_BACKEND",
    }
)


def _load_repo_dotenv() -> None:
    """Best-effort: load *known credential keys only* from a CWD .env into os.environ.

    Lets an LLM-assisted run pick up keys from a project dir; production may inject
    env vars directly. Never overrides existing env, never logs values, and — since a
    scanned repo may be untrusted — only ever sets keys in ``_DOTENV_ALLOWED_KEYS``.
    """
    from pathlib import Path

    env_path = Path.cwd() / ".env"
    if not env_path.is_file():
        return
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, _, value = line.partition("=")
        name = name.strip()
        if name in _DOTENV_ALLOWED_KEYS and name not in os.environ:
            os.environ[name] = value.strip().strip("'\"")


def resolve_api_key(env_var: str) -> str:
    """Return the API key from the environment (loading .env if needed), or raise."""
    from kolega_security_scanner.cli._errors import LLMConfigError

    key = os.environ.get(env_var)
    if not key:
        _load_repo_dotenv()
        key = os.environ.get(env_var)
    if not key:
        raise LLMConfigError(f"an LLM is required but no API key is set in ${env_var}")
    return key


def build_llm_client(env_var: str = "LITELLM_API_KEY") -> LLMClient:
    """Construct the default single-model client (``DEFAULT_MODEL``). Validates the key."""
    from kolega_security_scanner.llm._model_registry import DEFAULT_MODEL

    return build_llm_client_for_model(DEFAULT_MODEL, env_var)


def build_llm_client_for_model(model: str, env_var: str = "LITELLM_API_KEY") -> LLMClient:
    """Construct an LLM client for a ``provider/model`` spec.

    Direct mode (default): route to the provider's own endpoint + key —
    ``DEEPSEEK_API_KEY`` / ``MOONSHOT_API_KEY`` / ``OPENAI_API_KEY`` / ``ANTHROPIC_API_KEY``.
    OpenAI-compatible providers use ``LiteLLMClient``; Anthropic uses its native client.

    LiteLLM-proxy mode (``KOLEGA_LLM_BACKEND=litellm``): route every spec through one proxy
    (``LITELLM_URL`` + the ``env_var`` key, default ``LITELLM_API_KEY``), sending the spec verbatim.

    Used by matrix-mode scanners that run the same stage across several diverse models.
    """
    from kolega_security_scanner.llm._model_registry import resolve_provider, use_litellm

    if use_litellm():
        resolve_api_key(env_var)
        from kolega_security_scanner.llm.litellm_client import LiteLLMClient

        return LiteLLMClient.from_env(model=model)

    provider, raw_model = resolve_provider(model)
    key = resolve_api_key(provider.api_key_env)
    if provider.kind == "anthropic":
        from kolega_security_scanner.llm.anthropic_client import AnthropicClient

        return AnthropicClient(api_key=key, model=raw_model, base_url=provider.base_url)
    from kolega_security_scanner.llm.litellm_client import LiteLLMClient

    return LiteLLMClient(api_key=key, model=raw_model, base_url=provider.base_url)


__all__ = [
    "LLMClient",
    "AgentResult",
    "resolve_api_key",
    "build_llm_client",
    "build_llm_client_for_model",
]
