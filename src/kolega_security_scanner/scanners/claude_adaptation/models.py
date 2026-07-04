"""Dataclasses for the claude-adaptation pipeline (threat model -> candidate -> verdict).

These are the internal data carriers passed between the six-phase find-and-fix
loop's stages. They are deliberately separate from the public ``Finding`` schema:
``findings.py`` converts a confirmed ``Candidate`` into a wire-format ``Finding`` at
the boundary. All models are frozen (immutable).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ThreatModel:
    """Phase 1 output: the code-derived threat model used as downstream context.

    Faithful to the article's "code-driven derivation" step; the human-interview
    step is intentionally omitted because the CLI is non-interactive.
    """

    summary: str = ""
    assets: tuple[str, ...] = ()
    entry_points: tuple[str, ...] = ()
    trust_boundaries: tuple[str, ...] = ()
    trusted_inputs: tuple[str, ...] = ()
    vuln_classes: tuple[str, ...] = ()
    status: str = "ok"  # ok | no_llm | error:<detail>

    def as_context(self) -> str:
        """Render the threat model as a compact context block for downstream prompts."""
        if self.status != "ok" and not self.summary:
            return "(no threat model available)"
        parts = [f"SUMMARY: {self.summary}".strip()]
        if self.assets:
            parts.append("ASSETS: " + "; ".join(self.assets))
        if self.entry_points:
            parts.append("ENTRY POINTS: " + "; ".join(self.entry_points))
        if self.trust_boundaries:
            parts.append("TRUST BOUNDARIES: " + "; ".join(self.trust_boundaries))
        if self.trusted_inputs:
            parts.append("TRUSTED INPUTS (do NOT flag): " + "; ".join(self.trusted_inputs))
        if self.vuln_classes:
            parts.append("PRIORITY VULN CLASSES: " + "; ".join(self.vuln_classes))
        return "\n".join(p for p in parts if p)


@dataclass(frozen=True)
class Partition:
    """Phase 3a output: one attack-surface partition (a group of related files)."""

    name: str
    files: tuple[str, ...]


@dataclass(frozen=True)
class Candidate:
    """Phase 3 output: one unverified candidate vulnerability."""

    path: str
    line: int
    title: str
    vuln_class: str
    cwe: str
    rationale: str
    impact: str
    severity: str  # critical | high | medium | low | info
    confidence: str  # high | medium | low
    partition: str = ""
    end_line: int | None = None

    def dedupe_key(self) -> tuple[str, str]:
        """The (path, vuln_class) bucket used by deterministic dedupe."""
        return (self.path, self.vuln_class)


@dataclass(frozen=True)
class Verdict:
    """Phase 4 output: an independent verifier's ruling on one candidate."""

    exploitable: bool
    reason: str = ""
    severity: str | None = None  # verifier may recalibrate severity


@dataclass(frozen=True)
class VerifiedCandidate:
    """A candidate paired with its (possibly majority-voted) verdict."""

    candidate: Candidate
    verdict: Verdict
    votes: tuple[Verdict, ...] = field(default_factory=tuple)


__all__ = [
    "ThreatModel",
    "Partition",
    "Candidate",
    "Verdict",
    "VerifiedCandidate",
]
