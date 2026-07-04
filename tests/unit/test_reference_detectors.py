from pathlib import Path

from kolega_security_scanner.detectors.reference.example_command_injection import (
    CommandInjectionOsSystem,
)
from kolega_security_scanner.detectors.reference.example_hardcoded_secret import (
    HardcodedSecretLiteral,
)
from kolega_security_scanner.scanner.enumerate import enumerate_sources
from kolega_security_scanner.scanner.models import DetectorContext

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "scanner"
CTX = DetectorContext(llm=None)


def _run(det):
    target = enumerate_sources(FIX / "repo-mini")
    return list(det.run(target, CTX))


def test_hardcoded_secret_flags_py_and_js():
    fs = _run(HardcodedSecretLiteral())
    paths = {f.path for f in fs}
    assert "app.py" in paths and "routes.js" in paths
    assert all(f.extra.metadata.kolega.cluster_id == "example_hardcoded_secret" for f in fs)
    assert "safe.py" not in paths and "safe.js" not in paths


def test_command_injection_flags_py_and_js():
    fs = _run(CommandInjectionOsSystem())
    paths = {f.path for f in fs}
    assert "app.py" in paths and "routes.js" in paths
    assert "safe.py" not in paths and "safe.js" not in paths
    assert all(f.extra.metadata.cwe == ["CWE-78"] for f in fs)
