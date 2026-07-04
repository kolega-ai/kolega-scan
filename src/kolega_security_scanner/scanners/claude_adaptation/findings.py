r"""Convert confirmed pipeline candidates into wire-format ``Finding`` objects.

This is the boundary between the pipeline's internal models and the public Semgrep-
compatible schema. CWE ids are sanitized to the schema pattern (``^CWE-\d+$``) with a
generic fallback, and the verifier's recalibrated severity (if any) wins.
"""

from __future__ import annotations

import re

from kolega_security_scanner.scanners.claude_adaptation.models import VerifiedCandidate
from kolega_security_scanner.schema.finding import (
    Finding,
    FindingExtra,
    FindingMetadata,
    FindingMetadataKolega,
    StartOrEnd,
)

_CWE_RE = re.compile(r"CWE-\d+")
# CWE-693 "Protection Mechanism Failure" — generic fallback when the model omits/garbles
# a CWE, so the required (min_length=1) cwe field always validates.
_CWE_FALLBACK = "CWE-693"

_CHECK_ID_SLUG = re.compile(r"[^a-z0-9]+")


def _sanitize_cwe(raw: str) -> str:
    """Return a schema-valid CWE id (``CWE-123``), falling back if absent/malformed."""
    match = _CWE_RE.search(raw or "")
    return match.group(0) if match else _CWE_FALLBACK


def _check_id(vuln_class: str) -> str:
    """Stable namespaced check id, e.g. ``kolega.claude-adaptation.sql-injection``."""
    slug = _CHECK_ID_SLUG.sub("-", vuln_class.lower()).strip("-") or "finding"
    return f"kolega.claude-adaptation.{slug}"


def to_finding(vc: VerifiedCandidate) -> Finding:
    """Build a Finding from a verified candidate (verifier severity wins)."""
    c = vc.candidate
    severity = vc.verdict.severity or c.severity
    message = c.title
    if c.impact:
        message = f"{c.title} — {c.impact}"
    if vc.verdict.reason:
        message = f"{message} [verified: {vc.verdict.reason}]"

    kolega = FindingMetadataKolega(
        cluster_id=c.vuln_class,
        confidence=c.confidence,  # type: ignore[arg-type]  # validated literal upstream
    )
    return Finding(
        path=c.path,
        check_id=_check_id(c.vuln_class),
        start=StartOrEnd(line=c.line),
        end=StartOrEnd(line=c.end_line) if c.end_line is not None else None,
        extra=FindingExtra(
            message=message[:1000],
            severity=severity,  # type: ignore[arg-type]  # validated literal upstream
            metadata=FindingMetadata(cwe=[_sanitize_cwe(c.cwe)], kolega=kolega),
        ),
    )


__all__ = ["to_finding"]
