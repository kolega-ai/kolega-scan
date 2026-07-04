from kolega_security_scanner import __version__


def test_version_exact_stdout(run_cli):
    result = run_cli(["--version"])
    assert result.returncode == 0
    assert result.stdout == f"kolega-scan {__version__}\n"
    assert result.stderr == ""
