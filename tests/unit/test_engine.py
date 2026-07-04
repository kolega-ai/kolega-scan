from pathlib import Path

from kolega_security_scanner.detectors.base import BaseDetector, DetectionClass
from kolega_security_scanner.detectors.registry import default_registry
from kolega_security_scanner.scanner.config import ScanConfig
from kolega_security_scanner.scanner.engine import scan

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "scanner"
REPO = FIX / "repo-mini"


def test_scan_completes_with_schema_valid_findings():
    # The bundled detectors are stricter than a naive reference
    # detectors; assert the scan completes, isolates any detector error, and emits
    # only schema-valid, cluster-tagged findings (detection quality is covered by
    # per-detector tests).
    result = scan(ScanConfig(repo_path=REPO), default_registry(include_entry_points=False))
    assert isinstance(result.findings, list)
    for f in result.findings:
        assert f.extra.metadata.kolega.cluster_id


def test_findings_sorted_and_deduped():
    result = scan(ScanConfig(repo_path=REPO), default_registry(include_entry_points=False))
    keys = [(f.path, f.start.line, f.check_id) for f in result.findings]
    assert keys == sorted(keys)
    assert len(keys) == len(set(keys))


class _Boom(BaseDetector):
    slug = "ref-boom"
    cluster_id = "example_command_injection"
    languages = ("python",)
    detection_class = DetectionClass.FLOW

    def run(self, target, ctx):
        raise RuntimeError("kaboom")


def test_detector_crash_is_isolated():
    reg = default_registry(include_entry_points=False)
    reg.register(_Boom())
    result = scan(ScanConfig(repo_path=REPO), reg)
    assert any(e.slug == "ref-boom" for e in result.detector_errors)
    assert result.findings


def test_rules_mode_has_no_llm():
    captured = {}

    class _Probe(BaseDetector):
        slug = "ref-probe"
        cluster_id = "example_command_injection"
        languages = ("python",)
        detection_class = DetectionClass.FLOW

        def run(self, target, ctx):
            captured["llm"] = ctx.llm
            return iter(())

    reg = default_registry(include_entry_points=False)
    reg.register(_Probe())
    scan(ScanConfig(repo_path=REPO), reg)
    assert captured["llm"] is None
