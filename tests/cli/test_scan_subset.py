import json
from pathlib import Path

from typer.testing import CliRunner

from kolega_security_scanner.cli.main import app

runner = CliRunner()
REPO = str(Path(__file__).resolve().parents[1] / "fixtures" / "scanner" / "repo-mini")


def _scan_clusters(tmp_path, name, *extra):
    # Write to --out so we read clean JSON (CliRunner mixes stderr into .output).
    out = tmp_path / f"{name}.json"
    r = runner.invoke(app, ["scan", REPO, "--scanner", "detectors", "--out", str(out), *extra])
    assert r.exit_code == 0, r.output
    data = json.loads(out.read_text())
    findings = next(iter(data.values()))
    return {f["extra"]["metadata"]["kolega"]["cluster_id"] for f in findings}


def test_full_vs_subset_strict_subset(tmp_path):
    full = _scan_clusters(tmp_path, "full")
    sub = _scan_clusters(tmp_path, "sub", "--clusters", "example_command_injection")
    assert sub.issubset(full | {"example_command_injection"})
    assert sub <= {"example_command_injection"}


def test_detector_subset(tmp_path):
    clusters = _scan_clusters(tmp_path, "det", "--detectors", "ref-command-injection-os-system")
    assert clusters <= {"example_command_injection"}


def test_unknown_cluster_exit2(tmp_path):
    r = runner.invoke(app, ["scan", REPO, "--scanner", "detectors", "--clusters", "not_a_cluster"])
    assert r.exit_code == 2


def test_unknown_detector_exit2(tmp_path):
    r = runner.invoke(app, ["scan", REPO, "--scanner", "detectors", "--detectors", "nope"])
    assert r.exit_code == 2
