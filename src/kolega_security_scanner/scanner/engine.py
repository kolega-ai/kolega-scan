"""Scan engine: enumerate -> dispatch detectors (isolated) -> collect/dedupe/sort."""

from __future__ import annotations

import contextlib
import sys
from pathlib import Path

from kolega_security_scanner.cli._errors import DetectorError
from kolega_security_scanner.detectors.base import Detector
from kolega_security_scanner.detectors.registry import DetectorRegistry
from kolega_security_scanner.llm.client import LLMClient
from kolega_security_scanner.scanner.config import ScanConfig
from kolega_security_scanner.scanner.enumerate import enumerate_sources
from kolega_security_scanner.scanner.models import DetectorContext, DetectorRunError, ScanResult
from kolega_security_scanner.scanner.recon import ReconResult, build_recon
from kolega_security_scanner.schema.finding import Finding


def _dedupe_sort(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, int, tuple[str, ...]]] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.path, f.check_id, f.start.line, tuple(sorted(f.extra.metadata.cwe)))
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)

    def sort_key(f: Finding) -> tuple[str, int, str, str]:
        kolega = f.extra.metadata.kolega
        cluster = kolega.cluster_id if kolega and kolega.cluster_id else ""
        return (f.path, f.start.line, cluster, f.check_id)

    return sorted(unique, key=sort_key)


def _run_detector(det: Detector, target: object, ctx: DetectorContext) -> list[Finding]:
    out: list[Finding] = []
    for f in det.run(target, ctx):  # type: ignore[arg-type]
        kolega = f.extra.metadata.kolega
        if kolega and kolega.cluster_id and kolega.cluster_id != det.cluster_id:
            raise DetectorError(
                f"detector {det.slug} emitted cluster {kolega.cluster_id!r} "
                f"!= its cluster {det.cluster_id!r}"
            )
        out.append(f)
    return out


def scan(
    config: ScanConfig,
    registry: DetectorRegistry,
    llm: LLMClient | None = None,
) -> ScanResult:
    """Run the selected detectors over the repo and return a ScanResult.

    Recon is on by default (``config.recon``) but only *builds* when an LLM is
    available — with no LLM, recon is silently skipped so the deterministic path
    keeps working. The ``detectors`` provider adds a stricter guard that fails
    fast when a user *explicitly* asks for recon without an LLM.
    """
    target = enumerate_sources(config.repo_path)
    # Valid clusters are those declared by the registered detectors themselves
    # (the harness ships no fixed taxonomy).
    valid_clusters = {d.cluster_id for d in registry.all()}
    detectors = registry.select(config.clusters, config.detectors, valid_clusters)

    findings: list[Finding] = []
    errors: list[DetectorRunError] = []

    # Build the shared recon map at most once per repo, only when recon is enabled,
    # an LLM is available, and at least one selected detector declares needs_recon.
    recon: ReconResult | None = None
    if (
        config.recon
        and llm is not None
        and any(getattr(d, "needs_recon", False) for d in detectors)
    ):
        try:
            recon = build_recon(target, llm)
        except Exception as exc:  # noqa: BLE001 - isolate: a recon failure is not fatal
            errors.append(DetectorRunError(slug="recon", message=str(exc)))
            recon = None

    ctx = DetectorContext(llm=llm, recon=recon)
    # Redirect any detector stdout noise to stderr so machine-readable Finding
    # output on stdout stays clean.
    with contextlib.redirect_stdout(sys.stderr):
        for det in detectors:
            try:
                findings.extend(_run_detector(det, target, ctx))
            except Exception as exc:  # noqa: BLE001 - isolate-and-continue
                errors.append(DetectorRunError(slug=det.slug, message=str(exc)))

    return ScanResult(
        repo_dir=Path(config.repo_path).name,
        findings=_dedupe_sort(findings),
        detector_errors=tuple(errors),
    )


__all__ = [
    "scan",
]
