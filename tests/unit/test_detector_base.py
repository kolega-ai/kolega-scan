from kolega_security_scanner.detectors.base import BaseDetector, DetectionClass


class _Good(BaseDetector):
    slug = "ref-good-r1"
    cluster_id = "example_command_injection"
    languages = ("python",)
    detection_class = DetectionClass.FLOW

    def run(self, target, ctx):
        yield self._finding(path="a.py", line=1, cwe="CWE-78", message="x")


def test_finding_wires_cluster_and_check_id():
    f = next(_Good().run(None, None))
    assert f.check_id == "kolega.example_command_injection"
    assert f.extra.metadata.kolega.cluster_id == "example_command_injection"
    assert f.extra.metadata.kolega.detector_slug == "ref-good-r1"


def test_generic_slug_is_tagged():
    class Ref(_Good):
        slug = "ref-foo"

    f = next(Ref().run(None, None))
    assert f.extra.metadata.kolega.detector_slug == "ref-foo"


def test_invalid_slug_omits_detector_slug():
    class Bad(_Good):
        slug = "Has_Caps"  # not a valid slug -> field left unset

    f = next(Bad().run(None, None))
    assert f.extra.metadata.kolega.detector_slug is None
