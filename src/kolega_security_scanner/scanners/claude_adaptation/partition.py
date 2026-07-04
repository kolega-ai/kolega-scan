"""Phase 3a — partition the codebase by attack surface before discovery.

The article calls for partitioning so parallel discovery agents don't converge on the
same shallow bugs. We partition deterministically by top-level component (the first path
segment), then split oversized components into fixed-size chunks so each discovery prompt
stays within budget. A deterministic split keeps cost predictable and runs reproducible.
"""

from __future__ import annotations

from kolega_security_scanner.scanner.models import ScanTarget
from kolega_security_scanner.scanners.claude_adaptation.models import Partition

# Filenames that most often define entry points / trust boundaries — surfaced to the
# Phase 1 threat-model pass as representative source.
_ENTRY_HINTS = (
    "app",
    "main",
    "server",
    "wsgi",
    "asgi",
    "urls",
    "routes",
    "router",
    "api",
    "views",
    "handlers",
    "endpoints",
    "settings",
    "config",
    "auth",
    "middleware",
    "index",
    "__init__",
)


def _component(rel_path: str) -> str:
    """Top-level component for a repo-relative path (first dir, or '<root>')."""
    head, _, tail = rel_path.partition("/")
    return head if tail else "<root>"


def partition_files(target: ScanTarget, *, max_files: int) -> tuple[Partition, ...]:
    """Group source files by top-level component, splitting big groups into chunks."""
    by_component: dict[str, list[str]] = {}
    for sf in target.files:
        by_component.setdefault(_component(sf.path), []).append(sf.path)

    partitions: list[Partition] = []
    for name in sorted(by_component):
        files = sorted(by_component[name])
        if len(files) <= max_files:
            partitions.append(Partition(name=name, files=tuple(files)))
            continue
        for start in range(0, len(files), max_files):
            chunk = files[start : start + max_files]
            idx = start // max_files + 1
            partitions.append(Partition(name=f"{name} [{idx}]", files=tuple(chunk)))
    return tuple(partitions)


def select_entry_points(target: ScanTarget, *, max_files: int) -> tuple[str, ...]:
    """Pick representative entry-point files for the threat-model pass (budgeted)."""
    scored: list[tuple[tuple[int, int], str]] = []
    for sf in target.files:
        stem = sf.path.rsplit("/", 1)[-1].rsplit(".", 1)[0].lower()
        depth = sf.path.count("/")
        hit = any(h in stem for h in _ENTRY_HINTS)
        # Lower score sorts first: prefer entry-hint files and shallow paths.
        score = (0 if hit else 1, depth)
        scored.append((score, sf.path))
    scored.sort()
    return tuple(path for _, path in scored[:max_files])


__all__ = ["partition_files", "select_entry_points"]
