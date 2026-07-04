"""Phase 5 — triage: deduplicate confirmed findings and rank by severity.

Implements the article's deterministic deduplication pass: findings in the same
(file, vulnerability-class) bucket whose lines fall within a proximity window are treated
as one bug (same root cause / same missing protection), keeping the highest-severity
representative. The model-based qualification pass is a documented future extension; the
deterministic pass alone removes the bulk of near-duplicate noise at zero LLM cost.
"""

from __future__ import annotations

from kolega_security_scanner.scanners.claude_adaptation.models import VerifiedCandidate

# Two findings in the same file+class within this many lines are the same root cause.
_PROXIMITY_LINES = 10

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _effective_severity(vc: VerifiedCandidate) -> str:
    """Verifier-recalibrated severity wins over the discoverer's original."""
    return vc.verdict.severity or vc.candidate.severity


def _rank_of(vc: VerifiedCandidate) -> int:
    return _SEVERITY_RANK.get(_effective_severity(vc), 5)


def deduplicate(verified: list[VerifiedCandidate]) -> list[VerifiedCandidate]:
    """Collapse near-duplicate findings (same file+class within the proximity window)."""
    buckets: dict[tuple[str, str], list[VerifiedCandidate]] = {}
    for vc in verified:
        buckets.setdefault(vc.candidate.dedupe_key(), []).append(vc)

    kept: list[VerifiedCandidate] = []
    for members in buckets.values():
        members.sort(key=lambda vc: vc.candidate.line)
        clusters: list[list[VerifiedCandidate]] = []
        for vc in members:
            prev = clusters[-1][-1].candidate.line if clusters else None
            if prev is not None and vc.candidate.line - prev <= _PROXIMITY_LINES:
                clusters[-1].append(vc)
            else:
                clusters.append([vc])
        # Keep the highest-severity representative of each proximity cluster.
        kept.extend(min(cluster, key=_rank_of) for cluster in clusters)
    return kept


def rank(verified: list[VerifiedCandidate]) -> list[VerifiedCandidate]:
    """Sort findings by severity (critical first), then by location (stable, readable)."""
    return sorted(verified, key=lambda vc: (_rank_of(vc), vc.candidate.path, vc.candidate.line))


def triage(verified: list[VerifiedCandidate]) -> list[VerifiedCandidate]:
    """Phase 5 entry point: dedupe then rank the confirmed findings."""
    return rank(deduplicate(verified))


__all__ = ["triage", "deduplicate", "rank"]
