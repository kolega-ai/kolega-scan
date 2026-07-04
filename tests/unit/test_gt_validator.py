from pathlib import Path

import pytest

from kolega_security_scanner.cli._errors import ValidationError
from kolega_security_scanner.groundtruth.validator import validate_gt_dir, validate_gt_file

MIRROR = Path(__file__).resolve().parents[1] / "fixtures" / "realvuln-mirror"
VALID = MIRROR / "ground-truth"
INVALID = MIRROR / "invalid-gt"


@pytest.mark.parametrize(
    "repo",
    [
        "realvuln-alpha-human-py",
        "realvuln-bravo-llm-py",
        "realvuln-charlie-human-js",
        "realvuln-delta-llm-ts",
    ],
)
def test_valid_fixtures_pass(repo):
    validate_gt_file(VALID / repo / "ground-truth.json")  # no raise


def test_malformed_commit_sha_raises():
    with pytest.raises(ValidationError, match="commit_sha"):
        validate_gt_file(INVALID / "echo-bad-sha" / "ground-truth.json")


def test_primary_cwe_not_in_acceptable_raises():
    with pytest.raises(ValidationError, match="not in acceptable_cwes"):
        validate_gt_file(INVALID / "foxtrot-cwe-mismatch" / "ground-truth.json")


def test_missing_file_raises():
    with pytest.raises(ValidationError):
        validate_gt_file(VALID / "does-not-exist" / "ground-truth.json")


def test_validate_dir_collects_results():
    results = validate_gt_dir(VALID)
    assert len(results) == 4
    assert all(r.ok for r in results)


def test_validate_dir_missing_path_raises():
    with pytest.raises(ValidationError):
        validate_gt_dir(MIRROR / "nope")
