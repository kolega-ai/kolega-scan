"""Shared scan-time models (target, context, result)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from kolega_security_scanner.llm.client import LLMClient
from kolega_security_scanner.schema.finding import Finding

if TYPE_CHECKING:
    from kolega_security_scanner.scanner.recon import ReconResult


@dataclass(frozen=True)
class SourceFile:
    """One enumerated source file (repo-relative path + language)."""

    path: str
    language: str


@dataclass(frozen=True)
class ScanTarget:
    """The enumerated repo: root + source files + a lazy text reader."""

    repo_root: Path
    files: tuple[SourceFile, ...]

    def read_text(self, rel_path: str) -> str:
        """Read a repo-relative file as text (errors ignored)."""
        return (self.repo_root / rel_path).read_text(errors="ignore")


@dataclass(frozen=True)
class DetectorContext:
    """Per-run context handed to each detector.

    A detector's deterministic-vs-LLM behavior is driven by ``llm`` (a detector
    that wants an LLM no-ops when ``llm is None``), not by any mode flag.
    """

    llm: LLMClient | None = None
    recon: ReconResult | None = None


@dataclass(frozen=True)
class DetectorRunError:
    """An isolated detector failure (recorded, not fatal)."""

    slug: str
    message: str


@dataclass(frozen=True)
class ScanResult:
    """The outcome of a scan: findings + any isolated detector errors."""

    repo_dir: str
    findings: list[Finding] = field(default_factory=list)
    detector_errors: tuple[DetectorRunError, ...] = ()


__all__ = [
    "ScanTarget",
    "SourceFile",
    "DetectorContext",
    "DetectorRunError",
    "ScanResult",
]
