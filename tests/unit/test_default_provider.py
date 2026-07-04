"""The bundled default provider must delegate to the engine identically."""

from pathlib import Path

from kolega_security_scanner.detectors.registry import default_registry
from kolega_security_scanner.scanner.config import ScanConfig
from kolega_security_scanner.scanner.engine import scan as engine_scan
from kolega_security_scanner.scanner.models import ScanResult
from kolega_security_scanner.scanner.providers import DetectorScanProvider

REPO = Path(__file__).resolve().parents[1] / "fixtures" / "scanner" / "repo-mini"


def _cfg() -> ScanConfig:
    # A single cluster keeps the delegation test fast; the path under test is the
    # provider->engine wiring, which is independent of how many detectors run.
    return ScanConfig(
        repo_path=REPO,
        clusters=("example_command_injection",),
    )


def test_default_provider_returns_scan_result(no_llm_env):
    result = DetectorScanProvider().scan(_cfg())
    assert isinstance(result, ScanResult)
    assert result.repo_dir == "repo-mini"


def test_default_provider_matches_engine(no_llm_env):
    cfg = _cfg()
    via_provider = DetectorScanProvider().scan(cfg)
    via_engine = engine_scan(cfg, default_registry())

    def _keys(r: ScanResult):
        return [(f.path, f.start.line, f.check_id) for f in r.findings]

    assert _keys(via_provider) == _keys(via_engine)
    assert via_provider.repo_dir == via_engine.repo_dir
