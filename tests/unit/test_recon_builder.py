"""Unit tests for the shared recon builder (scanner/recon.py). T003, T004."""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from kolega_security_scanner.llm.fake import FakeLLMClient
from kolega_security_scanner.scanner.enumerate import enumerate_sources
from kolega_security_scanner.scanner.recon import (
    EndpointRecon,
    ReconResult,
    build_recon,
)

_APP = """\
from flask import Flask, request

app = Flask(__name__)


@app.route("/admin/delete", methods=["POST"])
def delete_user():
    uid = request.args.get("id")
    return _do_delete(uid)


@app.route("/health")
def health():
    return "ok"
"""


def _fixture_repo(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(_APP)
    return tmp_path


def test_build_recon_returns_frozen_result_and_filters(tmp_path: Path) -> None:
    repo = _fixture_repo(tmp_path)
    # Canned verdict: endpoint 0 missing_auth, endpoint 1 (a gate helper) must be filtered.
    canned = (
        '{"endpoints":[{"idx":0,"sensitive":true,"anon_reachable":true,'
        '"has_auth_gate":false,"is_gate_helper":false,"intended_access":"admin",'
        '"missing_auth":true,"reasoning":"app.py:7 anon delete"},'
        '{"idx":1,"sensitive":true,"anon_reachable":true,"has_auth_gate":false,'
        '"is_gate_helper":true,"missing_auth":true,"reasoning":"gate helper"}]}'
    )
    target = enumerate_sources(repo)
    result = build_recon(target, FakeLLMClient([canned]))

    assert isinstance(result, ReconResult)
    assert result.status in {"ok", "no_candidates", "no_llm"} or result.status.startswith(
        "partial:"
    )
    # missing_auth_endpoints() must exclude gate helpers even if missing_auth=True.
    for ep in result.missing_auth_endpoints():
        assert ep.missing_auth and not ep.is_gate_helper


def test_build_recon_no_llm_response_never_raises(tmp_path: Path) -> None:
    repo = _fixture_repo(tmp_path)
    target = enumerate_sources(repo)
    # FakeLLMClient with no canned responses -> chat_json returns None each call.
    result = build_recon(target, FakeLLMClient())
    assert isinstance(result, ReconResult)
    assert result.missing_auth_endpoints() == ()


def test_idor_risk_endpoints_filters_gate_helpers() -> None:
    a = EndpointRecon(
        file="a.py",
        line=1,
        end_line=2,
        name="get_acct",
        handler_kind="route",
        idor_risk=True,
        is_gate_helper=False,
    )
    helper = EndpointRecon(
        file="a.py",
        line=9,
        end_line=9,
        name="_gate",
        handler_kind="fn",
        idor_risk=True,
        is_gate_helper=True,
    )
    safe = EndpointRecon(
        file="a.py", line=20, end_line=21, name="list_all", handler_kind="route", idor_risk=False
    )
    res = ReconResult(repo="r", endpoints=(a, helper, safe))
    risks = res.idor_risk_endpoints()
    assert [e.name for e in risks] == ["get_acct"]


def test_recon_models_are_frozen_and_endpoints_is_tuple() -> None:
    ep = EndpointRecon(file="a.py", line=1, end_line=2, name="f", handler_kind="route")
    res = ReconResult(repo="r", endpoints=(ep,))
    assert isinstance(res.endpoints, tuple)
    with pytest.raises(dataclasses.FrozenInstanceError):
        ep.sensitive = True  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        res.status = "x"  # type: ignore[misc]
