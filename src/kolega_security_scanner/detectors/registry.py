"""Detector registry: in-process registration, selection, and discovery."""

from __future__ import annotations

import logging

from kolega_security_scanner.cli._errors import DetectorDiscoveryError, UsageError
from kolega_security_scanner.detectors.base import Detector

log = logging.getLogger(__name__)

ENTRY_POINT_GROUP = "kolega_security_scanner.detectors"


class DetectorRegistry:
    """Holds discovered/registered detectors, addressable by slug and cluster."""

    def __init__(self) -> None:
        """Create an empty registry."""
        self._by_slug: dict[str, Detector] = {}

    def register(self, detector: Detector) -> None:
        """Register a detector; duplicate slug raises DetectorDiscoveryError."""
        if detector.slug in self._by_slug:
            raise DetectorDiscoveryError(f"duplicate detector slug: {detector.slug}")
        self._by_slug[detector.slug] = detector

    def all(self) -> list[Detector]:
        """All detectors, sorted by slug (deterministic)."""
        return [self._by_slug[s] for s in sorted(self._by_slug)]

    def by_cluster(self, cluster_id: str) -> list[Detector]:
        """Detectors targeting a cluster, sorted by slug."""
        return [d for d in self.all() if d.cluster_id == cluster_id]

    def select(
        self,
        clusters: tuple[str, ...] | None = None,
        detectors: tuple[str, ...] | None = None,
        valid_clusters: set[str] | None = None,
    ) -> list[Detector]:
        """Return the selected detectors; unknown ids raise UsageError."""
        chosen = self.all()
        if detectors is not None:
            unknown = sorted(set(detectors) - set(self._by_slug))
            if unknown:
                raise UsageError(f"unknown detector(s): {', '.join(unknown)}")
            chosen = [d for d in chosen if d.slug in detectors]
        if clusters is not None:
            if valid_clusters is not None:
                unknown_c = sorted(set(clusters) - valid_clusters)
                if unknown_c:
                    raise UsageError(f"unknown cluster(s): {', '.join(unknown_c)}")
            chosen = [d for d in chosen if d.cluster_id in clusters]
        return chosen

    def discover(self, *, include_entry_points: bool = True) -> None:
        """Merge entry-point-registered detectors into this registry."""
        if not include_entry_points:
            return
        from importlib.metadata import entry_points

        for ep in entry_points(group=ENTRY_POINT_GROUP):
            try:
                factory = ep.load()
                detector = factory() if callable(factory) else factory
                self.register(detector)
            except Exception as exc:  # noqa: BLE001 - a bad/duplicate plugin is skipped, never fatal
                log.warning("skipping detector entry point %s: %s", ep.name, exc)


def default_registry(*, include_entry_points: bool = True) -> DetectorRegistry:
    """A registry with the bundled reference detectors plus discovered externals."""
    from kolega_security_scanner.detectors.reference.example_command_injection import (
        CommandInjectionOsSystem,
    )
    from kolega_security_scanner.detectors.reference.example_hardcoded_secret import (
        HardcodedSecretLiteral,
    )
    from kolega_security_scanner.detectors.reference.llm_secret_confirm import LlmSecretConfirm

    reg = DetectorRegistry()
    reg.register(HardcodedSecretLiteral())
    reg.register(CommandInjectionOsSystem())
    reg.register(LlmSecretConfirm())
    reg.discover(include_entry_points=include_entry_points)
    # The public harness ships only the bundled reference detectors above plus any
    # detectors discovered via the entry-point group. Additional detector providers
    # register at runtime from separately installed distributions.
    return reg
