from pathlib import Path

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "realvuln-mirror"


def test_validate_gt_valid_dir_exit0(run_cli):
    result = run_cli(["validate-gt", str(FIX / "ground-truth")])
    assert result.returncode == 0
    ok_lines = [ln for ln in result.stdout.splitlines() if ln.startswith("OK ")]
    assert len(ok_lines) == 4
    assert ok_lines == sorted(ok_lines)  # deterministic sorted output


def test_validate_gt_invalid_exit1(run_cli):
    result = run_cli(["validate-gt", str(FIX / "invalid-gt")])
    assert result.returncode == 1
    assert result.stderr.strip() != ""


def test_validate_gt_missing_path_exit2(run_cli):
    result = run_cli(["validate-gt", str(FIX / "does-not-exist")])
    assert result.returncode == 2
