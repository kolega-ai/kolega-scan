from pathlib import Path

from kolega_security_scanner.detectors.base import BaseDetector, DetectionClass
from kolega_security_scanner.detectors.registry import DetectorRegistry
from kolega_security_scanner.llm.fake import FakeLLMClient
from kolega_security_scanner.scanner.config import ScanConfig
from kolega_security_scanner.scanner.engine import scan

REPO = Path(__file__).resolve().parents[1] / "fixtures" / "scanner" / "repo-mini"


def test_hybrid_passes_llm_to_context():
    captured = {}

    class _Probe(BaseDetector):
        slug = "ref-probe-llm"
        cluster_id = "example_command_injection"
        languages = ("python",)
        detection_class = DetectionClass.FLOW

        def run(self, target, ctx):
            captured["llm"] = ctx.llm
            if ctx.llm is not None:
                captured["answer"] = ctx.llm.complete("is this vulnerable?")
            return iter(())

    # Bare registry with just the probe: this test verifies the engine injects the
    # LLM into a detector's context, independent of which detectors default_registry
    # ships (a reference LLM detector would otherwise consume the canned response).
    reg = DetectorRegistry()
    reg.register(_Probe())
    fake = FakeLLMClient(["yes"])
    scan(ScanConfig(repo_path=REPO), reg, llm=fake)
    assert captured["llm"] is fake
    assert captured["answer"] == "yes"
