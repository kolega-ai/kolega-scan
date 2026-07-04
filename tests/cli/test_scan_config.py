import json
from pathlib import Path

from typer.testing import CliRunner

from kolega_security_scanner.cli.main import app

runner = CliRunner()
REPO = str(Path(__file__).resolve().parents[1] / "fixtures" / "scanner" / "repo-mini")


def test_config_clusters_applied(tmp_path):
    cfg = tmp_path / "scan.yaml"
    cfg.write_text("clusters:\n  - example_command_injection\n")
    out = tmp_path / "o.json"
    r = runner.invoke(
        app, ["scan", REPO, "--scanner", "detectors", "--config", str(cfg), "--out", str(out)]
    )
    assert r.exit_code == 0, r.output
    data = json.loads(out.read_text())
    clusters = {f["extra"]["metadata"]["kolega"]["cluster_id"] for f in next(iter(data.values()))}
    assert clusters <= {"example_command_injection"}


def test_cli_flag_overrides_config(tmp_path):
    cfg = tmp_path / "scan.yaml"
    cfg.write_text("clusters:\n  - example_command_injection\n")
    out = tmp_path / "o.json"
    # --detectors on CLI for a different cluster should win over config clusters
    r = runner.invoke(
        app,
        [
            "scan",
            REPO,
            "--scanner",
            "detectors",
            "--config",
            str(cfg),
            "--detectors",
            "ref-command-injection-os-system",
            "--out",
            str(out),
        ],
    )
    assert r.exit_code == 0


def test_missing_config_exit2(tmp_path):
    r = runner.invoke(app, ["scan", REPO, "--config", str(tmp_path / "nope.yaml")])
    assert r.exit_code == 2
