"""LLM handling lives behind the provider boundary; the CLI stays LLM-agnostic."""

from pathlib import Path

from typer.testing import CliRunner

from kolega_security_scanner.cli.main import app

runner = CliRunner()
REPO = str(Path(__file__).resolve().parents[1] / "fixtures" / "scanner" / "repo-mini")


def test_llm_scanner_missing_key_exit2(no_llm_env):
    # The default scanner builds its own client inside scan(); with no key in the
    # environment (and no .env to pick up) it raises LLMConfigError -> exit 2.
    r = runner.invoke(app, ["scan", REPO])
    assert r.exit_code == 2
    assert "api key" in r.output.lower()


def test_detectors_builds_client_when_key_resolves(monkeypatch, tmp_path):
    # The detectors provider opportunistically builds a client; inject a fake so
    # no network is hit and the scan still succeeds.
    import kolega_security_scanner.llm.client as _m
    from kolega_security_scanner.llm.fake import FakeLLMClient

    monkeypatch.setattr(_m, "build_llm_client", lambda env_var="LITELLM_API_KEY": FakeLLMClient([]))
    r = runner.invoke(
        app,
        ["scan", REPO, "--scanner", "detectors", "--out", str(tmp_path / "o.json")],
    )
    assert r.exit_code == 0


def test_detectors_ignores_missing_key(no_llm_env):
    # The detectors provider treats a missing key as "no LLM", not an error:
    # the scan just runs deterministically.
    r = runner.invoke(app, ["scan", REPO, "--scanner", "detectors"])
    assert r.exit_code == 0
