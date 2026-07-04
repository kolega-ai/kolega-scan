"""Deterministic, repo-keyed Finding JSON serialization (scoreable by `score`)."""

from __future__ import annotations

import json

from kolega_security_scanner.scanner.models import ScanResult


def to_repo_keyed(result: ScanResult) -> dict[str, list[dict[str, object]]]:
    """Return ``{repo_dir: [finding-dict, ...]}`` for the scan result."""
    return {result.repo_dir: [f.model_dump() for f in result.findings]}


def dumps(result: ScanResult) -> str:
    """Serialize the scan result deterministically (sorted keys)."""
    return json.dumps(to_repo_keyed(result), indent=2, sort_keys=True) + "\n"
