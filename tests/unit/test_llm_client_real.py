import pytest

from kolega_security_scanner.cli._errors import LLMConfigError
from kolega_security_scanner.llm.litellm_client import LiteLLMClient, parse_json_loose


def test_from_env_reads_key_and_url(monkeypatch):
    monkeypatch.setenv("LITELLM_API_KEY", "secret")
    monkeypatch.delenv("LITELLM_BASE_URL", raising=False)
    monkeypatch.setenv("LITELLM_URL", "https://llm.example/v1")
    c = LiteLLMClient.from_env(model="moonshot/kimi-k2.6")
    assert c.base_url == "https://llm.example/v1"
    assert c.api_key == "secret"
    # spec passed through verbatim for the proxy to route
    assert c.model == "moonshot/kimi-k2.6"


def test_from_env_missing_key_raises(monkeypatch):
    monkeypatch.delenv("LITELLM_API_KEY", raising=False)
    with pytest.raises(LLMConfigError):
        LiteLLMClient.from_env()


def test_chat_and_chat_json_via_mocked_post(monkeypatch):
    c = LiteLLMClient(api_key="k", model="m", base_url="http://x/v1")
    payloads = {"choices": [{"message": {"content": '```json\n{"vuln": true}\n```'}}]}
    monkeypatch.setattr(c, "_post", lambda payload: (200, payloads))
    assert c.chat([{"role": "user", "content": "hi"}]) is not None
    assert c.chat_json([{"role": "user", "content": "hi"}]) == {"vuln": True}


def test_chat_returns_none_on_failure(monkeypatch):
    c = LiteLLMClient(api_key="k", model="m", retries=0)
    monkeypatch.setattr(c, "_post", lambda payload: (500, "err"))
    assert c.chat([{"role": "user", "content": "x"}]) is None


def test_preflight_pong(monkeypatch):
    c = LiteLLMClient(api_key="k", model="m")
    monkeypatch.setattr(c, "chat", lambda *a, **k: "pong")
    assert c.preflight() is True


def test_parse_json_loose():
    assert parse_json_loose('noise {"a": 1} tail') == {"a": 1}
    assert parse_json_loose("nope") is None
