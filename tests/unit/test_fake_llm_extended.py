from kolega_security_scanner.llm.fake import FakeLLMClient


def test_chat_and_preflight():
    c = FakeLLMClient(["hello"])
    assert c.chat([{"role": "user", "content": "x"}]) == "hello"
    assert c.preflight() is True


def test_chat_json_parses():
    c = FakeLLMClient(['{"ok": true}'])
    assert c.chat_json([{"role": "user", "content": "x"}]) == {"ok": True}


def test_chat_json_none_on_nonjson():
    c = FakeLLMClient(["not json"])
    assert c.chat_json([{"role": "user", "content": "x"}]) is None
