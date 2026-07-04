import pytest

from kolega_security_scanner.cli._errors import SliceCycleError, SliceReferenceError
from kolega_security_scanner.groundtruth.slices import resolve_slice


def _write(d, name, body):
    (d / f"{name}.yaml").write_text(body)


def test_terminal_sorted_dedup(tmp_path):
    _write(tmp_path, "human-curated", "repos:\n  - realvuln-beta\n  - realvuln-alpha\n")
    assert resolve_slice("human-curated", tmp_path) == ["realvuln-alpha", "realvuln-beta"]


def test_one_level_include(tmp_path):
    _write(tmp_path, "human-curated", "repos:\n  - realvuln-alpha\n")
    _write(tmp_path, "js-ts", "repos:\n  - realvuln-beta\n")
    _write(tmp_path, "all", "include:\n  - human-curated\n  - js-ts\n")
    assert resolve_slice("all", tmp_path) == ["realvuln-alpha", "realvuln-beta"]


def test_multi_level_include(tmp_path):
    _write(tmp_path, "leaf", "repos:\n  - realvuln-alpha\n")
    _write(tmp_path, "mid", "include:\n  - leaf\n")
    _write(tmp_path, "top", "include:\n  - mid\n")
    assert resolve_slice("top", tmp_path) == ["realvuln-alpha"]


def test_cycle_raises_naming_cycle(tmp_path):
    _write(tmp_path, "sa", "include:\n  - sb\n")
    _write(tmp_path, "sb", "include:\n  - sa\n")
    with pytest.raises(SliceCycleError, match="sa -> sb -> sa"):
        resolve_slice("sa", tmp_path)


def test_missing_reference_raises(tmp_path):
    _write(tmp_path, "sc", "include:\n  - ghost\n")
    with pytest.raises(SliceReferenceError, match="ghost"):
        resolve_slice("sc", tmp_path)
