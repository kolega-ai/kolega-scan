"""The stable detector interface (Protocol + ABC) and emission helpers."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Iterable
from enum import Enum
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from kolega_security_scanner.schema.finding import (
    Finding,
    FindingExtra,
    FindingMetadata,
    FindingMetadataKolega,
    StartOrEnd,
)

if TYPE_CHECKING:
    from kolega_security_scanner.scanner.models import DetectorContext, ScanTarget

_DETECTOR_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]*$")


class DetectionClass(str, Enum):  # noqa: UP042  (StrEnum is 3.11+, floor is 3.10)
    """How a detector finds its cluster (informational)."""

    FLOW = "FLOW"
    REGEX = "REGEX"
    SEMANTIC = "SEMANTIC"
    ABSENCE = "ABSENCE"


@runtime_checkable
class Detector(Protocol):
    """The public detector contract (structural — external detectors implement it)."""

    slug: str
    cluster_id: str
    languages: tuple[str, ...]
    detection_class: DetectionClass
    needs_recon: bool

    def run(self, target: ScanTarget, ctx: DetectorContext) -> Iterable[Finding]:
        """Yield Findings for this detector's cluster."""
        ...


class BaseDetector(ABC):
    """Ergonomic base for bundled detectors. Subclasses set the class attributes."""

    slug: str
    cluster_id: str
    languages: tuple[str, ...]
    detection_class: DetectionClass
    # Capability flag: when True, the engine builds the shared recon map (when
    # recon is enabled + an LLM is available) and injects it via DetectorContext.
    # The engine reads this with getattr(d, "needs_recon", False), so detectors
    # predating the field — and external detectors — remain backward-compatible.
    needs_recon: bool = False

    @abstractmethod
    def run(self, target: ScanTarget, ctx: DetectorContext) -> Iterable[Finding]:
        """Yield Findings for this detector's cluster."""

    def _finding(
        self,
        *,
        path: str,
        line: int,
        cwe: str,
        message: str,
        severity: str = "medium",
        end_line: int | None = None,
        confidence: str | None = None,
    ) -> Finding:
        """Build a Phase 1 Finding tagged with this detector's cluster/slug."""
        kolega = FindingMetadataKolega(
            cluster_id=self.cluster_id,
            detector_slug=self.slug if _DETECTOR_SLUG.match(self.slug) else None,
            confidence=confidence,  # type: ignore[arg-type]
        )
        return Finding(
            path=path,
            check_id=f"kolega.{self.cluster_id}",
            start=StartOrEnd(line=line),
            end=StartOrEnd(line=end_line) if end_line is not None else None,
            extra=FindingExtra(
                message=message,
                severity=severity,  # type: ignore[arg-type]
                metadata=FindingMetadata(cwe=[cwe], kolega=kolega),
            ),
        )
