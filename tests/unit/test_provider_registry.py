import pytest

from kolega_security_scanner.cli._errors import ProviderDiscoveryError, UsageError
from kolega_security_scanner.scanner.providers import (
    DEFAULT_PROVIDER,
    DetectorScanProvider,
    ProviderRegistry,
    default_provider_registry,
)


class _FakeProvider:
    def __init__(self, name="fake"):
        self.name = name

    def scan(self, config):
        from kolega_security_scanner.scanner.models import ScanResult

        return ScanResult(repo_dir="fake", findings=[])


class _FakeEP:
    def __init__(self, name, obj, boom=False):
        self.name = name
        self._obj = obj
        self._boom = boom

    def load(self):
        if self._boom:
            raise ImportError("cannot import")
        return self._obj


def _patch_eps(monkeypatch, eps):
    import importlib.metadata as md

    monkeypatch.setattr(md, "entry_points", lambda group=None: eps)


def test_register_and_get():
    reg = ProviderRegistry()
    reg.register(_FakeProvider("a"))
    reg.register(_FakeProvider("b"))
    assert reg.names() == ["a", "b"]
    assert reg.get("a").name == "a"
    assert [p.name for p in reg.all()] == ["a", "b"]


def test_duplicate_name_raises():
    reg = ProviderRegistry()
    reg.register(_FakeProvider("a"))
    with pytest.raises(ProviderDiscoveryError, match="duplicate"):
        reg.register(_FakeProvider("a"))


def test_get_unknown_raises_usage_error():
    reg = ProviderRegistry()
    reg.register(_FakeProvider("a"))
    with pytest.raises(UsageError, match="unknown scanner"):
        reg.get("nope")


def test_detector_provider_name_is_detectors():
    from kolega_security_scanner.scanner.providers import DETECTORS_PROVIDER

    assert DetectorScanProvider().name == DETECTORS_PROVIDER == "detectors"


def test_default_provider_is_v1():
    assert DEFAULT_PROVIDER == "kolega-scan-oss-v1"


def test_default_registry_contains_both_providers():
    reg = default_provider_registry(include_entry_points=False)
    assert "detectors" in reg.names()
    assert "kolega-scan-oss-ref" in reg.names()
    assert "kolega-scan-oss-v1" in reg.names()
    assert "kolega-scan-oss-v2" in reg.names()
    # The default resolves to the 2-model matrix provider.
    assert reg.get(DEFAULT_PROVIDER).name == "kolega-scan-oss-v1"


def test_discovers_external_provider(monkeypatch):
    _patch_eps(monkeypatch, [_FakeEP("ext", _FakeProvider)])
    reg = ProviderRegistry()
    reg.discover()
    assert any(p.name == "fake" for p in reg.all())


def test_discover_duplicate_name_skipped(monkeypatch):
    # A conflicting third-party plugin is skipped-with-warning, never fatal.
    _patch_eps(monkeypatch, [_FakeEP("ext", _FakeProvider)])
    reg = ProviderRegistry()
    reg.register(_FakeProvider("fake"))
    reg.discover()  # must not raise
    assert len(reg.all()) == 1


def test_discover_import_failure_skipped(monkeypatch):
    _patch_eps(monkeypatch, [_FakeEP("bad", None, boom=True)])
    reg = ProviderRegistry()
    reg.discover()  # must not raise
    assert reg.all() == []


def test_discover_disabled_is_noop(monkeypatch):
    _patch_eps(monkeypatch, [_FakeEP("ext", _FakeProvider)])
    reg = ProviderRegistry()
    reg.discover(include_entry_points=False)
    assert reg.all() == []
