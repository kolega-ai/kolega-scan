from pathlib import Path

from kolega_security_scanner.detectors.registry import default_registry
from kolega_security_scanner.scanner.config import ScanConfig
from kolega_security_scanner.scanner.engine import scan

REPO = Path(__file__).resolve().parents[1] / "fixtures" / "scanner" / "repo-mini"


def test_full_detector_set_scans_crash_isolated():
    # Running every bundled detector over a small repo must not raise; any detector
    # that errors is isolated and recorded, never fatal.
    result = scan(ScanConfig(repo_path=REPO), default_registry(include_entry_points=False))
    # findings are schema-valid Findings; detector_errors (if any) are recorded, not raised
    assert isinstance(result.findings, list)
    for f in result.findings:
        assert f.extra.metadata.kolega.cluster_id
