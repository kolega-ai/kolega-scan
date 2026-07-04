"""In-process CLI tests via Typer CliRunner (counted for coverage).

The subprocess tests assert real exit codes and stream discipline; these cover
the command bodies so coverage reflects the CLI logic.
"""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from kolega_security_scanner import __version__
from kolega_security_scanner.cli.main import app

runner = CliRunner()
FIX = Path(__file__).resolve().parents[1] / "fixtures" / "realvuln-mirror"


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert f"kolega-scan {__version__}" in result.output


def test_no_subcommand_exits_2():
    result = runner.invoke(app, [])
    assert result.exit_code == 2


def test_scan_runs_rules_mode():
    repo = Path(__file__).resolve().parents[1] / "fixtures" / "scanner" / "repo-mini"
    result = runner.invoke(app, ["scan", str(repo), "--scanner", "detectors"])
    assert result.exit_code == 0


def test_validate_gt_ok():
    result = runner.invoke(app, ["validate-gt", str(FIX / "ground-truth")])
    assert result.exit_code == 0
    assert "OK " in result.output


def test_validate_gt_fail():
    result = runner.invoke(app, ["validate-gt", str(FIX / "invalid-gt")])
    assert result.exit_code == 1


def test_validate_gt_missing():
    result = runner.invoke(app, ["validate-gt", str(FIX / "nope")])
    assert result.exit_code == 2


def test_import_success(monkeypatch, gt_source_repo, scanner_dest):
    monkeypatch.chdir(scanner_dest)
    result = runner.invoke(
        app, ["import-published-gt", "--realvuln-path", str(gt_source_repo), "--yes"]
    )
    assert result.exit_code == 0
    assert (scanner_dest / "ground-truth" / "slices" / "all.yaml").is_file()


def test_import_prompt_accept(monkeypatch, gt_source_repo, scanner_dest):
    monkeypatch.chdir(scanner_dest)
    result = runner.invoke(
        app,
        ["import-published-gt", "--realvuln-path", str(gt_source_repo)],
        input="y\n",
    )
    assert result.exit_code == 0


def test_import_prompt_abort(monkeypatch, gt_source_repo, scanner_dest):
    monkeypatch.chdir(scanner_dest)
    result = runner.invoke(
        app,
        ["import-published-gt", "--realvuln-path", str(gt_source_repo)],
        input="n\n",
    )
    assert result.exit_code == 0
    assert not (scanner_dest / "ground-truth" / "slices" / "all.yaml").exists()


def test_import_dirty(monkeypatch, gt_source_repo, scanner_dest):
    (gt_source_repo / "dirty.txt").write_text("x")
    monkeypatch.chdir(scanner_dest)
    result = runner.invoke(
        app, ["import-published-gt", "--realvuln-path", str(gt_source_repo), "--yes"]
    )
    assert result.exit_code == 1


def test_import_nonempty_no_force(monkeypatch, gt_source_repo, scanner_dest):
    (scanner_dest / "ground-truth" / "findings" / "x").mkdir()
    monkeypatch.chdir(scanner_dest)
    result = runner.invoke(
        app, ["import-published-gt", "--realvuln-path", str(gt_source_repo), "--yes"]
    )
    assert result.exit_code == 1


def test_import_force_overwrites(monkeypatch, gt_source_repo, scanner_dest):
    (scanner_dest / "ground-truth" / "findings" / "x").mkdir()
    monkeypatch.chdir(scanner_dest)
    result = runner.invoke(
        app,
        ["import-published-gt", "--realvuln-path", str(gt_source_repo), "--yes", "--force"],
    )
    assert result.exit_code == 0


def test_import_non_git(monkeypatch, tmp_path, scanner_dest):
    plain = tmp_path / "plain"
    plain.mkdir()
    monkeypatch.chdir(scanner_dest)
    result = runner.invoke(app, ["import-published-gt", "--realvuln-path", str(plain), "--yes"])
    assert result.exit_code == 2
