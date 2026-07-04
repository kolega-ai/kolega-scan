from pathlib import Path

from kolega_security_scanner.detectors.reference.llm_secret_confirm import LlmSecretConfirm
from kolega_security_scanner.llm.fake import FakeLLMClient
from kolega_security_scanner.scanner.enumerate import enumerate_sources
from kolega_security_scanner.scanner.models import DetectorContext

REPO = Path(__file__).resolve().parents[1] / "fixtures" / "scanner" / "repo-mini"


def _run(client):
    det = LlmSecretConfirm()
    return list(det.run(enumerate_sources(REPO), DetectorContext(llm=client)))


def test_emits_when_llm_confirms():
    fs = _run(FakeLLMClient(['{"is_secret": true}'] * 5))
    assert fs and all(f.extra.metadata.kolega.cluster_id == "example_hardcoded_secret" for f in fs)


def test_no_finding_when_llm_denies():
    fs = _run(FakeLLMClient(['{"is_secret": false}'] * 5))
    assert fs == []


def test_noop_in_rules_mode():
    det = LlmSecretConfirm()
    fs = list(det.run(enumerate_sources(REPO), DetectorContext(llm=None)))
    assert fs == []
