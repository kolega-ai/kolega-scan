"""Direct-provider routing + LiteLLM-proxy backend selection."""

import pytest

from kolega_security_scanner.cli._errors import LLMConfigError
from kolega_security_scanner.llm._model_registry import (
    PROVIDERS,
    resolve_provider,
    split_spec,
    use_litellm,
)
from kolega_security_scanner.llm.client import build_llm_client_for_model


def test_split_spec_requires_provider_slash_model():
    assert split_spec("deepseek/deepseek-v4-flash") == ("deepseek", "deepseek-v4-flash")
    for bad in ("deepseek-v4-flash", "deepseek/", "/model", ""):
        with pytest.raises(LLMConfigError):
            split_spec(bad)


def test_resolve_provider_maps_endpoints_and_keys():
    prov, model = resolve_provider("deepseek/deepseek-v4-flash")
    assert prov.base_url == "https://api.deepseek.com/v1"
    assert prov.api_key_env == "DEEPSEEK_API_KEY"
    assert model == "deepseek-v4-flash"
    # kimi is an alias for moonshot
    assert resolve_provider("kimi/kimi-k2.6")[0].name == "moonshot"
    assert PROVIDERS["anthropic"].kind == "anthropic"


def test_resolve_provider_unknown_raises():
    with pytest.raises(LLMConfigError):
        resolve_provider("bogus/model")


def test_use_litellm_env_toggle(monkeypatch):
    monkeypatch.delenv("KOLEGA_LLM_BACKEND", raising=False)
    assert use_litellm() is False
    monkeypatch.setenv("KOLEGA_LLM_BACKEND", "litellm")
    assert use_litellm() is True


def test_direct_openai_provider_builds_litellm_client(monkeypatch):
    from kolega_security_scanner.llm.litellm_client import LiteLLMClient

    monkeypatch.delenv("KOLEGA_LLM_BACKEND", raising=False)
    monkeypatch.setenv("DEEPSEEK_API_KEY", "dk")
    c = build_llm_client_for_model("deepseek/deepseek-v4-flash")
    assert isinstance(c, LiteLLMClient)
    assert c.base_url == "https://api.deepseek.com/v1"
    assert c.model == "deepseek-v4-flash"  # raw id, no provider prefix
    assert c.api_key == "dk"


def test_direct_anthropic_provider_builds_native_client(monkeypatch):
    from kolega_security_scanner.llm.anthropic_client import AnthropicClient

    monkeypatch.delenv("KOLEGA_LLM_BACKEND", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ak")
    c = build_llm_client_for_model("anthropic/claude-opus-4-6")
    assert isinstance(c, AnthropicClient)
    assert c.model == "claude-opus-4-6"
    assert c.messages_url == "https://api.anthropic.com/v1/messages"


def test_litellm_backend_routes_through_proxy(monkeypatch):
    from kolega_security_scanner.llm.litellm_client import LiteLLMClient

    monkeypatch.setenv("KOLEGA_LLM_BACKEND", "litellm")
    monkeypatch.setenv("LITELLM_API_KEY", "lk")
    monkeypatch.setenv("LITELLM_URL", "https://proxy.example/v1")
    c = build_llm_client_for_model("deepseek/deepseek-v4-flash")
    assert isinstance(c, LiteLLMClient)
    assert c.base_url == "https://proxy.example/v1"
    assert c.model == "deepseek/deepseek-v4-flash"  # verbatim spec for proxy routing


def test_anthropic_client_lifts_system_message():
    from kolega_security_scanner.llm.anthropic_client import AnthropicClient

    c = AnthropicClient(api_key="k", model="claude-opus-4-6")
    captured = {}

    def fake_post(payload):
        captured.update(payload)
        return 200, {"content": [{"type": "text", "text": "ok"}]}

    c._post = fake_post  # type: ignore[method-assign]
    out = c.chat([{"role": "system", "content": "sys"}, {"role": "user", "content": "hi"}])
    assert out == "ok"
    assert captured["system"] == "sys"
    assert captured["messages"] == [{"role": "user", "content": "hi"}]
