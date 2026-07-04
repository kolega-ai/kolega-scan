"""Model-spec parsing + provider endpoints for the LLM backends.

A model spec is ``provider/model`` — e.g. ``deepseek/deepseek-v4-flash``,
``moonshot/kimi-k2.6``, ``openai/gpt-5.4``, ``anthropic/claude-opus-4-6``. The provider
prefix selects the endpoint + API key; the rest is the raw model id sent to that provider.

Backends (env ``KOLEGA_LLM_BACKEND``):
  * ``direct`` (default) — call each provider at its own endpoint with its own key
    (``DEEPSEEK_API_KEY`` / ``MOONSHOT_API_KEY`` / ``OPENAI_API_KEY`` / ``ANTHROPIC_API_KEY``).
    All are OpenAI-compatible except Anthropic, which uses its native Messages API.
  * ``litellm`` — route every spec through one LiteLLM proxy (``LITELLM_URL`` +
    ``LITELLM_API_KEY``); the ``provider/model`` spec is sent verbatim for the proxy to route.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

# Default single-model spec (the model the pipeline was tuned + measured on).
DEFAULT_MODEL = "deepseek/deepseek-v4-flash"

BACKEND_ENV = "KOLEGA_LLM_BACKEND"


@dataclass(frozen=True)
class Provider:
    """A direct-call LLM provider: where to reach it and which key env var to read."""

    name: str
    base_url: str
    api_key_env: str
    # "openai" -> OpenAI-compatible /chat/completions; "anthropic" -> native /messages.
    kind: str = "openai"


# Direct-provider endpoints. Kimi is Moonshot's model, so both prefixes route there.
PROVIDERS: dict[str, Provider] = {
    "deepseek": Provider("deepseek", "https://api.deepseek.com/v1", "DEEPSEEK_API_KEY"),
    "moonshot": Provider("moonshot", "https://api.moonshot.ai/v1", "MOONSHOT_API_KEY"),
    "kimi": Provider("moonshot", "https://api.moonshot.ai/v1", "MOONSHOT_API_KEY"),
    "openai": Provider("openai", "https://api.openai.com/v1", "OPENAI_API_KEY"),
    "anthropic": Provider(
        "anthropic", "https://api.anthropic.com/v1", "ANTHROPIC_API_KEY", kind="anthropic"
    ),
}


def use_litellm() -> bool:
    """True when the LiteLLM-proxy backend is selected (``KOLEGA_LLM_BACKEND=litellm``)."""
    return os.environ.get(BACKEND_ENV, "direct").strip().lower() == "litellm"


def split_spec(spec: str) -> tuple[str, str]:
    """Split ``provider/model`` into ``(provider_key, model)``; raise if not that shape."""
    from kolega_security_scanner.cli._errors import LLMConfigError

    prov, sep, model = spec.partition("/")
    if not sep or not prov.strip() or not model.strip():
        raise LLMConfigError(
            f"model must be 'provider/model' (e.g. deepseek/deepseek-v4-flash); got {spec!r}"
        )
    return prov.strip().lower(), model.strip()


def resolve_provider(spec: str) -> tuple[Provider, str]:
    """Resolve a ``provider/model`` spec to its ``Provider`` and raw model id (direct mode)."""
    from kolega_security_scanner.cli._errors import LLMConfigError

    prov_key, model = split_spec(spec)
    prov = PROVIDERS.get(prov_key)
    if prov is None:
        known = ", ".join(sorted(PROVIDERS))
        raise LLMConfigError(f"unknown provider {prov_key!r}; known: {known}")
    return prov, model
