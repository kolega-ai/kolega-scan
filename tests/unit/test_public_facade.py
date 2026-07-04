import re

import kolega_security_scanner as k


def test_all_names_resolve():
    for name in k.__all__:
        assert hasattr(k, name), name


def test_version_is_semver():
    assert re.fullmatch(r"\d+\.\d+\.\d+([.-].+)?", k.__version__)


def test_gtimporterror_present_and_no_builtin_shadow():
    assert hasattr(k, "GtImportError")
    assert "ImportError" not in k.__all__  # builtin not shadowed in the public surface


def test_no_internal_symbol_exported():
    # nothing underscore-prefixed (except __version__) is advertised
    leaked = [n for n in k.__all__ if n.startswith("_") and n != "__version__"]
    assert leaked == []


def test_provisional_llm_symbols_present():
    assert hasattr(k, "LLMClient") and hasattr(k, "AgentResult")
