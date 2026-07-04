import json
from pathlib import Path

from typer.testing import CliRunner

from kolega_security_scanner.cli.main import app

runner = CliRunner()
REPO = str(Path(__file__).resolve().parents[1] / "fixtures" / "scanner" / "repo-mini")


def test_default_scanner_is_claude_adaptation(no_llm_env, tmp_path):
    """The default provider is the LLM pipeline; with no API key it fails fast (exit 2).

    The provider (not the CLI) builds the client and raises; the message names the
    env var to set.
    """
    r = runner.invoke(app, ["scan", REPO, "--out", str(tmp_path / "default.json")])
    assert r.exit_code == 2, r.output
    assert "api key" in r.output.lower()
    assert "_API_KEY" in r.output  # the message names the missing env var


def test_explicit_detectors_provider_runs_offline(no_llm_env, tmp_path):
    """The detectors provider still runs with no LLM available."""
    explicit_out = tmp_path / "explicit.json"
    r = runner.invoke(app, ["scan", REPO, "--scanner", "detectors", "--out", str(explicit_out)])
    assert r.exit_code == 0, r.output
    assert explicit_out.exists()


def test_unknown_scanner_exit2(tmp_path):
    r = runner.invoke(app, ["scan", REPO, "--scanner", "does-not-exist"])
    assert r.exit_code == 2


def test_scanner_flag_selects_registered_provider(tmp_path, monkeypatch):
    """A provider registered in the registry is selectable end-to-end via --scanner."""
    from kolega_security_scanner.scanner import providers as prov
    from kolega_security_scanner.scanner.models import ScanResult

    class _FakeProvider:
        name = "fake"

        def scan(self, config):
            # A distinctive repo_dir keys the output JSON, proving the fake ran.
            return ScanResult(repo_dir="SENTINEL", findings=[])

    def _registry(*, include_entry_points=True):
        reg = prov.ProviderRegistry()
        reg.register(prov.DetectorScanProvider())
        reg.register(_FakeProvider())
        return reg

    monkeypatch.setattr(prov, "default_provider_registry", _registry)
    out = tmp_path / "fake.json"
    r = runner.invoke(app, ["scan", REPO, "--scanner", "fake", "--out", str(out)])
    assert r.exit_code == 0, r.output
    assert list(json.loads(out.read_text()).keys()) == ["SENTINEL"]
