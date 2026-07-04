import os
from pathlib import Path

from typer.testing import CliRunner

import kolega_security_scanner.llm.client as llm_client_mod
from kolega_security_scanner.cli.main import app
from kolega_security_scanner.llm.fake import FakeLLMClient

runner = CliRunner()
REPO = str(Path(__file__).resolve().parents[1] / "fixtures" / "scanner" / "repo-mini")


def test_injected_client_no_network(monkeypatch, tmp_path):
    monkeypatch.setattr(
        llm_client_mod, "build_llm_client", lambda env_var="LITELLM_API_KEY": FakeLLMClient(["{}"])
    )
    out = tmp_path / "h.json"
    r = runner.invoke(app, ["scan", REPO, "--scanner", "detectors", "--out", str(out)])
    assert r.exit_code == 0, r.output
    assert out.is_file()


def test_llm_scanner_missing_key_exit2(no_llm_env):
    # The default scanner needs an LLM; the *provider* raises LLMConfigError when no
    # key is configured, and the CLI maps it to a usage error.
    r = runner.invoke(app, ["scan", REPO])
    assert r.exit_code == 2


def test_detectors_runs_without_client(no_llm_env, tmp_path):
    # The detectors provider does not require an LLM: with no key configured the
    # scan runs deterministically and succeeds.
    out = tmp_path / "r.json"
    r = runner.invoke(app, ["scan", REPO, "--scanner", "detectors", "--out", str(out)])
    assert r.exit_code == 0
    assert out.is_file()


def test_real_llm_live_optin(tmp_path):
    # End-to-end live run of the DEFAULT scanner (kolega-scan-oss-v1, the 2-model
    # DeepSeek flash+pro pipeline; one DEEPSEEK_API_KEY covers both models) against a tiny
    # inline fixture repo (kept minimal so the live LLM run stays fast and cheap).
    import pytest

    if os.environ.get("KOLEGA_LLM_LIVE") != "1":
        pytest.skip("real LLM disabled; set KOLEGA_LLM_LIVE=1 to run")
    if not os.environ.get("DEEPSEEK_API_KEY"):
        pytest.skip("DEEPSEEK_API_KEY not set; the default scanner needs a live key")

    import json

    repo = tmp_path / "live-fixture-repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "import os\n"
        "import sqlite3\n"
        "\n"
        "\n"
        "def run_user_command(user_input: str) -> int:\n"
        "    # command injection: user input passed straight to a shell\n"
        '    return os.system("ping -c 1 " + user_input)\n'
        "\n"
        "\n"
        "def get_user(conn: sqlite3.Connection, name: str):\n"
        "    # SQL injection: string-formatted query\n"
        "    return conn.execute(\"SELECT * FROM users WHERE name = '%s'\" % name)\n"
    )
    out = tmp_path / "live-findings.json"
    r = runner.invoke(app, ["scan", str(repo), "--out", str(out)])
    assert r.exit_code == 0, r.output
    findings = json.loads(out.read_text())
    assert isinstance(findings, (list, dict))
