from pathlib import Path

from kolega_security_scanner.detectors.registry import default_registry
from kolega_security_scanner.scanner.config import ScanConfig
from kolega_security_scanner.scanner.engine import scan
from kolega_security_scanner.scanner.output import dumps, to_repo_keyed
from kolega_security_scanner.schema.finding import Finding

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "scanner"
REPO = FIX / "repo-mini"


def test_repo_keyed_and_schema_valid():
    result = scan(ScanConfig(repo_path=REPO), default_registry(include_entry_points=False))
    payload = to_repo_keyed(result)
    assert "repo-mini" in payload
    for item in payload["repo-mini"]:
        Finding.model_validate(item)


def test_dumps_byte_stable():
    a = dumps(scan(ScanConfig(repo_path=REPO), default_registry(include_entry_points=False)))
    b = dumps(scan(ScanConfig(repo_path=REPO), default_registry(include_entry_points=False)))
    assert a == b
