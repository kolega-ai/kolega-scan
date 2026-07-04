"""Ground-truth file validator.

Validation rules are implemented here directly so the package has no external
dependency. The published corpus uses a nested ``location.{start_line,end_line}``
block and an open ``evidence.source`` set, and treats the FP-trap ratio as
advisory — this validator matches that reality. A flat ``start_line``/``end_line``
fallback is also accepted for forgiveness.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from kolega_security_scanner.cli._errors import ValidationError

_COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_CWE = re.compile(r"^CWE-\d+$")

_TOP_LEVEL_REQUIRED = ("repo_id", "commit_sha", "language", "authorship", "findings")
_FINDING_REQUIRED = (
    "id",
    "file",
    "primary_cwe",
    "acceptable_cwes",
    "is_vulnerable",
    "severity",
    "evidence",
)
_FP_TRAP_MIN_RATIO = 0.2  # advisory only: >= 1 FP trap per 5 vulnerable findings


@dataclass(frozen=True)
class GtValidationResult:
    """Outcome of validating a single GT file."""

    path: Path
    errors: tuple[str, ...]
    warnings: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        """True when the file has no validation errors (warnings are allowed)."""
        return not self.errors


def _finding_location(f: dict[str, object]) -> tuple[object, object]:
    """Return ``(start_line, end_line)`` from nested ``location`` or flat fields."""
    loc = f.get("location")
    if isinstance(loc, dict):
        return loc.get("start_line"), loc.get("end_line")
    return f.get("start_line"), f.get("end_line")


def _collect(gt: object) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(gt, dict):
        return ["root must be a JSON object"], warnings

    for key in _TOP_LEVEL_REQUIRED:
        if key not in gt:
            errors.append(f"missing required top-level key: {key}")

    sha = gt.get("commit_sha")
    if isinstance(sha, str) and not _COMMIT_SHA.match(sha):
        errors.append(f"commit_sha must be 40 hex chars, got {sha!r}")

    findings = gt.get("findings")
    if not isinstance(findings, list):
        errors.append("findings must be a list")
        return errors, warnings

    vuln = fp = 0
    for i, f in enumerate(findings):
        fid = f.get("id", f"findings[{i}]") if isinstance(f, dict) else f"findings[{i}]"
        if not isinstance(f, dict):
            errors.append(f"[{fid}] finding must be an object")
            continue
        for key in _FINDING_REQUIRED:
            if key not in f:
                errors.append(f"[{fid}] missing required field: {key}")

        if f.get("is_vulnerable") is True:
            vuln += 1
        elif f.get("is_vulnerable") is False:
            fp += 1

        start, end = _finding_location(f)
        if start is None:
            errors.append(f"[{fid}] missing location (location.start_line or start_line)")
        if isinstance(start, int) and start < 1:
            errors.append(f"[{fid}] start_line must be >= 1, got {start}")
        if isinstance(start, int) and isinstance(end, int) and end < start:
            errors.append(f"[{fid}] end_line ({end}) < start_line ({start})")

        primary = f.get("primary_cwe")
        if isinstance(primary, str) and not _CWE.match(primary):
            errors.append(f"[{fid}] primary_cwe format invalid: {primary!r}")
        acceptable = f.get("acceptable_cwes")
        if isinstance(acceptable, list) and isinstance(primary, str) and primary:
            if primary not in acceptable:
                errors.append(f"[{fid}] primary_cwe {primary} not in acceptable_cwes")

        ev = f.get("evidence")
        if isinstance(ev, dict):
            src = ev.get("source")
            if not isinstance(src, str) or not src:
                errors.append(f"[{fid}] evidence.source must be a non-empty string")
        elif "evidence" in f:
            errors.append(f"[{fid}] evidence must be an object")

    if vuln > 0 and fp < vuln * _FP_TRAP_MIN_RATIO:
        warnings.append(
            f"low FP-trap ratio: {fp} traps for {vuln} vulnerable findings "
            f"(recommend >= {vuln * _FP_TRAP_MIN_RATIO:.1f})"
        )
    return errors, warnings


def validate_gt_file(path: str | Path) -> None:
    """Validate a single ``ground-truth.json``.

    Raises:
        ValidationError: If the file is missing, unparseable, or violates any
            rule. The message lists every problem found. Advisory warnings (e.g.
            a low FP-trap ratio) do not raise.
    """
    gt_path = Path(path)
    if not gt_path.is_file():
        raise ValidationError(f"{gt_path}: not a file")
    try:
        gt = json.loads(gt_path.read_text())
    except json.JSONDecodeError as exc:
        raise ValidationError(f"{gt_path}: invalid JSON: {exc}") from exc

    errors, _ = _collect(gt)
    if errors:
        raise ValidationError(f"{gt_path}: " + "; ".join(errors))


def validate_gt_dir(path: str | Path) -> list[GtValidationResult]:
    """Validate every ``ground-truth.json`` under a directory (recursively).

    Returns:
        One result per file, sorted by path. Never raises on validation
        failure (collect-and-report); raises only on a missing directory.
    """
    root = Path(path)
    if not root.exists():
        raise ValidationError(f"{root}: path does not exist")

    targets = [root] if root.is_file() else sorted(root.rglob("ground-truth.json"))

    results: list[GtValidationResult] = []
    for gt_path in targets:
        try:
            gt = json.loads(gt_path.read_text())
            errors, warnings = _collect(gt)
        except json.JSONDecodeError as exc:
            errors, warnings = [f"invalid JSON: {exc}"], []
        results.append(GtValidationResult(gt_path, tuple(errors), tuple(warnings)))
    return results
