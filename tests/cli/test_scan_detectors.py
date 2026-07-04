import json
from pathlib import Path

from typer.testing import CliRunner

from kolega_security_scanner.cli.main import app
from kolega_security_scanner.schema.finding import Finding

runner = CliRunner()
FIX = Path(__file__).resolve().parents[1] / "fixtures" / "scanner"
REPO = FIX / "repo-mini"


def test_scan_detectors_exit0_schema_valid(tmp_path):
    out = tmp_path / "o.json"
    r = runner.invoke(app, ["scan", str(REPO), "--scanner", "detectors", "--out", str(out)])
    assert r.exit_code == 0, r.output
    data = json.loads(out.read_text())
    assert "repo-mini" in data
    for item in data["repo-mini"]:
        Finding.model_validate(item)


def test_scan_out_file_and_stable(tmp_path):
    o1, o2 = tmp_path / "1.json", tmp_path / "2.json"
    runner.invoke(app, ["scan", str(REPO), "--scanner", "detectors", "--out", str(o1)])
    runner.invoke(app, ["scan", str(REPO), "--scanner", "detectors", "--out", str(o2)])
    assert o1.read_text() == o2.read_text()


def test_scan_missing_repo_exit2():
    r = runner.invoke(app, ["scan", str(FIX / "nope")])
    assert r.exit_code == 2
