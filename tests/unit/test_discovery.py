from kolega_security_scanner.detectors.base import BaseDetector, DetectionClass
from kolega_security_scanner.detectors.registry import DetectorRegistry


class _ExternalDet(BaseDetector):
    slug = "ref-external-r1"
    cluster_id = "example_command_injection"
    languages = ("python",)
    detection_class = DetectionClass.FLOW

    def run(self, target, ctx):
        return iter(())


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
    import kolega_security_scanner.detectors.registry as reg_mod

    monkeypatch.setattr(reg_mod, "entry_points", lambda group=None: eps, raising=False)
    # registry.discover imports entry_points locally from importlib.metadata
    import importlib.metadata as md

    monkeypatch.setattr(md, "entry_points", lambda group=None: eps)


def test_discovers_external(monkeypatch):
    _patch_eps(monkeypatch, [_FakeEP("ext", _ExternalDet)])
    reg = DetectorRegistry()
    reg.discover()
    assert any(d.slug == "ref-external-r1" for d in reg.all())


def test_duplicate_slug_skipped(monkeypatch):
    # A conflicting third-party plugin is skipped-with-warning, never fatal.
    _patch_eps(monkeypatch, [_FakeEP("ext", _ExternalDet)])
    reg = DetectorRegistry()
    reg.register(_ExternalDet())
    reg.discover()  # must not raise
    assert len(reg.all()) == 1


def test_import_failure_skipped(monkeypatch):
    _patch_eps(monkeypatch, [_FakeEP("bad", None, boom=True)])
    reg = DetectorRegistry()
    reg.discover()  # must not raise
    assert reg.all() == []
