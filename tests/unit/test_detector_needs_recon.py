"""US2 — detector manifest declares needs_recon. T014, T015."""

from __future__ import annotations

from collections.abc import Iterable

from kolega_security_scanner.detectors.base import BaseDetector, DetectionClass, Detector
from kolega_security_scanner.scanner.models import DetectorContext, ScanTarget
from kolega_security_scanner.schema.finding import Finding


class _PlainDetector(BaseDetector):
    slug = "ref-plain"
    cluster_id = "c"
    languages = ("python",)
    detection_class = DetectionClass.REGEX

    def run(self, target: ScanTarget, ctx: DetectorContext) -> Iterable[Finding]:
        return []


class _ReconDetector(BaseDetector):
    slug = "ref-recon"
    cluster_id = "c"
    languages = ("python",)
    detection_class = DetectionClass.ABSENCE
    needs_recon = True

    def run(self, target: ScanTarget, ctx: DetectorContext) -> Iterable[Finding]:
        return []


def test_needs_recon_defaults_false_and_can_opt_in() -> None:
    assert _PlainDetector().needs_recon is False
    assert _ReconDetector().needs_recon is True


def test_engine_reads_flag_via_getattr_without_running() -> None:
    # A detector predating the field has no attribute; getattr default must be False.
    class _Legacy:
        slug = "x"
        cluster_id = "c"
        languages = ("python",)
        detection_class = DetectionClass.REGEX

    assert getattr(_Legacy(), "needs_recon", False) is False
    assert getattr(_ReconDetector(), "needs_recon", False) is True


def test_recon_detector_satisfies_protocol() -> None:
    assert isinstance(_ReconDetector(), Detector)
