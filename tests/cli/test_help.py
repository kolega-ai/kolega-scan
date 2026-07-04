import pytest


@pytest.mark.parametrize(
    "args",
    [
        ["--help"],
        ["scan", "--help"],
        ["validate-gt", "--help"],
        ["import-published-gt", "--help"],
    ],
)
def test_help_exits_zero_to_stdout(run_cli, args):
    result = run_cli(args)
    assert result.returncode == 0
    assert result.stdout.strip() != ""
