"""US1 — `--recon` CLI flag, default on, fail-fast, config-file. T008-T010."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from kolega_security_scanner.cli.main import app
from kolega_security_scanner.scanner.config import ScanConfig
from kolega_security_scanner.scanner.models import ScanResult

runner = CliRunner()

_APP = (
    "from flask import Flask, request\n"
    "app = Flask(__name__)\n"
    "@app.route('/admin/delete', methods=['POST'])\n"
    "def delete_user():\n"
    "    return _do(request.args.get('id'))\n"
)


def _repo(tmp_path: Path) -> str:
    (tmp_path / "app.py").write_text(_APP)
    return str(tmp_path)


def _capture_config(monkeypatch: Any) -> dict[str, ScanConfig]:
    """Patch engine.scan to capture the ScanConfig and skip the real scan."""
    import kolega_security_scanner.scanner.engine as eng

    box: dict[str, ScanConfig] = {}

    def _fake_scan(config: ScanConfig, registry: Any, llm: Any = None) -> ScanResult:
        box["cfg"] = config
        return ScanResult(repo_dir="r", findings=[])

    monkeypatch.setattr(eng, "scan", _fake_scan)
    return box


def test_recon_default_on(no_llm_env, monkeypatch: Any, tmp_path: Path) -> None:
    # Recon is ON by default; not passing the flag (and no config) -> recon True but
    # not explicit. No LLM here: the default-on case degrades silently in the provider.
    box = _capture_config(monkeypatch)
    r = runner.invoke(app, ["scan", "--scanner", "detectors", _repo(tmp_path)])
    assert r.exit_code == 0
    assert box["cfg"].recon is True
    assert box["cfg"].recon_explicit is False


def test_recon_flag_sets_config(monkeypatch: Any, tmp_path: Path) -> None:
    box = _capture_config(monkeypatch)
    # Inject a fake client so the provider's explicit-recon guard is satisfied.
    import kolega_security_scanner.llm.client as _m
    from kolega_security_scanner.llm.fake import FakeLLMClient

    monkeypatch.setattr(_m, "build_llm_client", lambda env_var="LITELLM_API_KEY": FakeLLMClient([]))
    r = runner.invoke(app, ["scan", "--scanner", "detectors", _repo(tmp_path), "--recon"])
    assert r.exit_code == 0
    assert box["cfg"].recon is True
    assert box["cfg"].recon_explicit is True


def test_recon_without_llm_exits_2(no_llm_env, monkeypatch: Any, tmp_path: Path) -> None:
    # No LLM available -> an EXPLICIT --recon must fail fast with a usage error.
    # The guard now lives in the detectors provider, not the CLI.
    r = runner.invoke(app, ["scan", "--scanner", "detectors", _repo(tmp_path), "--recon"])
    assert r.exit_code == 2
    assert "--recon requires an LLM" in r.output


def test_config_file_recon_and_flag_override(monkeypatch: Any, tmp_path: Path) -> None:
    box = _capture_config(monkeypatch)
    import kolega_security_scanner.llm.client as _m
    from kolega_security_scanner.llm.fake import FakeLLMClient

    monkeypatch.setattr(_m, "build_llm_client", lambda env_var="LITELLM_API_KEY": FakeLLMClient([]))
    cfg_file = tmp_path / "scan.yaml"
    cfg_file.write_text("recon: true\n")

    # YAML recon: true honored (but not an explicit CLI demand).
    r = runner.invoke(
        app,
        [
            "scan",
            "--scanner",
            "detectors",
            _repo(tmp_path),
            "--config",
            str(cfg_file),
        ],
    )
    assert r.exit_code == 0
    assert box["cfg"].recon is True
    assert box["cfg"].recon_explicit is False

    # Explicit --no-recon overrides the config value.
    r2 = runner.invoke(
        app,
        [
            "scan",
            "--scanner",
            "detectors",
            _repo(tmp_path),
            "--no-recon",
            "--config",
            str(cfg_file),
        ],
    )
    assert r2.exit_code == 0
    assert box["cfg"].recon is False
    assert box["cfg"].recon_explicit is False


def test_stdout_is_pure_json_with_recon_off(no_llm_env, tmp_path: Path) -> None:
    # FR-014/C-CLI-5: structured stdout stays parseable; recon adds no stdout noise.
    r = runner.invoke(app, ["scan", "--scanner", "detectors", _repo(tmp_path)])
    assert r.exit_code in (0, 1)
    json.loads(r.stdout)  # must parse
