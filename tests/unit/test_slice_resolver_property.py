from hypothesis import given, settings
from hypothesis import strategies as st

from kolega_security_scanner.cli._errors import SliceCycleError
from kolega_security_scanner.groundtruth.slices import resolve_slice


def _names(n):
    return [f"s{i:02d}" for i in range(n)]


@given(n=st.integers(min_value=2, max_value=8))
@settings(max_examples=25, deadline=None)
def test_acyclic_dag_resolves(tmp_path_factory, n):
    d = tmp_path_factory.mktemp("acyclic")
    names = _names(n)
    # Edges only point to higher indices -> guaranteed acyclic.
    for i, name in enumerate(names):
        if i == n - 1:
            d.joinpath(f"{name}.yaml").write_text("repos:\n  - realvuln-leaf\n")
        else:
            d.joinpath(f"{name}.yaml").write_text(f"include:\n  - {names[i + 1]}\n")
    assert resolve_slice(names[0], d) == ["realvuln-leaf"]


@given(n=st.integers(min_value=2, max_value=6))
@settings(max_examples=15, deadline=None)
def test_injected_cycle_raises(tmp_path_factory, n):
    d = tmp_path_factory.mktemp("cyclic")
    names = _names(n)
    for i, name in enumerate(names):
        nxt = names[(i + 1) % n]  # ring -> cycle
        d.joinpath(f"{name}.yaml").write_text(f"include:\n  - {nxt}\n")
    try:
        resolve_slice(names[0], d)
        raise AssertionError("expected a cycle error")
    except SliceCycleError:
        pass
