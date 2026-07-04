import pytest

from kolega_security_scanner.cli._errors import DetectorDiscoveryError, UsageError
from kolega_security_scanner.detectors.base import BaseDetector, DetectionClass
from kolega_security_scanner.detectors.registry import DetectorRegistry


def _det(slug, cluster):
    class D(BaseDetector):
        def run(self, target, ctx):
            return iter(())

    D.slug = slug
    D.cluster_id = cluster
    D.languages = ("python",)
    D.detection_class = DetectionClass.REGEX
    return D()


def test_register_and_lookup():
    reg = DetectorRegistry()
    reg.register(_det("ref-a", "c1"))
    reg.register(_det("ref-b", "c2"))
    assert [d.slug for d in reg.all()] == ["ref-a", "ref-b"]
    assert reg.by_cluster("c1")[0].slug == "ref-a"


def test_duplicate_slug_raises():
    reg = DetectorRegistry()
    reg.register(_det("ref-a", "c1"))
    with pytest.raises(DetectorDiscoveryError, match="duplicate"):
        reg.register(_det("ref-a", "c2"))


def test_select_all_when_no_subset():
    reg = DetectorRegistry()
    reg.register(_det("ref-a", "c1"))
    assert len(reg.select()) == 1


def test_select_by_cluster_and_slug():
    reg = DetectorRegistry()
    reg.register(_det("ref-a", "c1"))
    reg.register(_det("ref-b", "c2"))
    assert [d.slug for d in reg.select(clusters=("c1",), valid_clusters={"c1", "c2"})] == ["ref-a"]
    assert [d.slug for d in reg.select(detectors=("ref-b",))] == ["ref-b"]


def test_select_unknown_detector_raises():
    reg = DetectorRegistry()
    reg.register(_det("ref-a", "c1"))
    with pytest.raises(UsageError, match="unknown detector"):
        reg.select(detectors=("nope",))


def test_select_unknown_cluster_raises():
    reg = DetectorRegistry()
    reg.register(_det("ref-a", "c1"))
    with pytest.raises(UsageError, match="unknown cluster"):
        reg.select(clusters=("ghost",), valid_clusters={"c1"})
