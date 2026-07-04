import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from kolega_security_scanner.schema.finding import Finding

CANONICAL = json.loads(
    (Path(__file__).resolve().parents[1] / "fixtures" / "findings" / "canonical.json").read_text()
)


def test_roundtrip_canonical():
    finding = Finding.model_validate(CANONICAL)
    assert finding.model_dump(exclude_none=False)["path"] == CANONICAL["path"]
    again = Finding.model_validate(finding.model_dump())
    assert again == finding


def _mutate(**overrides):
    data = json.loads(json.dumps(CANONICAL))
    data.update(overrides)
    return data


def test_rejects_uppercase_severity():
    data = json.loads(json.dumps(CANONICAL))
    data["extra"]["severity"] = "High"
    with pytest.raises(ValidationError):
        Finding.model_validate(data)


def test_rejects_empty_cwe_list():
    data = json.loads(json.dumps(CANONICAL))
    data["extra"]["metadata"]["cwe"] = []
    with pytest.raises(ValidationError):
        Finding.model_validate(data)


def test_rejects_malformed_cwe():
    data = json.loads(json.dumps(CANONICAL))
    data["extra"]["metadata"]["cwe"] = ["CWE89"]
    with pytest.raises(ValidationError):
        Finding.model_validate(data)


def test_rejects_extra_top_level_key():
    with pytest.raises(ValidationError):
        Finding.model_validate(_mutate(unexpected="x"))


def test_rejects_negative_line():
    data = json.loads(json.dumps(CANONICAL))
    data["start"]["line"] = 0
    with pytest.raises(ValidationError):
        Finding.model_validate(data)


def test_rejects_end_before_start():
    data = json.loads(json.dumps(CANONICAL))
    data["end"]["line"] = 1
    with pytest.raises(ValidationError):
        Finding.model_validate(data)


def test_rejects_absolute_path():
    with pytest.raises(ValidationError):
        Finding.model_validate(_mutate(path="/etc/passwd"))


def test_rejects_parent_path_segment():
    with pytest.raises(ValidationError):
        Finding.model_validate(_mutate(path="../secrets.py"))


def test_finding_is_frozen():
    finding = Finding.model_validate(CANONICAL)
    with pytest.raises(ValidationError):
        finding.path = "other.py"
