from pathlib import Path

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "scanner" / "repo-mini"


def test_scan_runs_in_rules_mode(run_cli):
    result = run_cli(["scan", str(FIX), "--scanner", "detectors"])
    assert result.returncode == 0
