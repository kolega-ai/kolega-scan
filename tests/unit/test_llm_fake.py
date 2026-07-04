import pytest

from kolega_security_scanner.cli._errors import LLMConfigError
from kolega_security_scanner.llm.client import AgentResult, resolve_api_key
from kolega_security_scanner.llm.fake import FakeLLMClient


def test_fake_complete_returns_canned():
    c = FakeLLMClient(["a", "b"])
    assert c.complete("p1") == "a"
    assert c.complete("p2") == "b"
    assert c.complete("p3") == ""  # exhausted


def test_fake_run_agent():
    c = FakeLLMClient(["agent-out"])
    r = c.run_agent("sys", [], [])
    assert isinstance(r, AgentResult)
    assert r.output == "agent-out"


def test_resolve_api_key_missing(monkeypatch):
    monkeypatch.delenv("KOLEGA_LLM_API_KEY", raising=False)
    with pytest.raises(LLMConfigError):
        resolve_api_key("KOLEGA_LLM_API_KEY")


def test_resolve_api_key_present(monkeypatch):
    monkeypatch.setenv("KOLEGA_LLM_API_KEY", "secret")
    assert resolve_api_key("KOLEGA_LLM_API_KEY") == "secret"
