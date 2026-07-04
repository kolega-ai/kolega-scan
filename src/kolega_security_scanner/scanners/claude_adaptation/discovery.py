"""Phase 3 — discovery: fan out one structured pass per partition (maximize recall).

Each partition gets an independent discovery call so the model does not converge on the
same shallow bugs across the whole repo. Output is parsed defensively into ``Candidate``
objects; malformed rows are dropped rather than crashing the run, and line numbers are
clamped to the cited file so downstream code positions are always valid.
"""

from __future__ import annotations

from typing import Any

from kolega_security_scanner.llm.client import LLMClient
from kolega_security_scanner.scanner.models import ScanTarget
from kolega_security_scanner.scanners.claude_adaptation import prompts
from kolega_security_scanner.scanners.claude_adaptation.coderender import render_partition
from kolega_security_scanner.scanners.claude_adaptation.config import PipelineConfig
from kolega_security_scanner.scanners.claude_adaptation.models import (
    Candidate,
    Partition,
    ThreatModel,
)

_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_CONFIDENCES = {"high", "medium", "low"}


def _valid_path(target: ScanTarget, path: str) -> str | None:
    """Return the path if it is a known source file, else None (model may hallucinate)."""
    known = {sf.path for sf in target.files}
    return path if path in known else None


def _clamp_line(target: ScanTarget, path: str, line: int) -> int:
    """Clamp a 1-based line to the file's bounds (defends against off-by/hallucinated)."""
    try:
        n = len(target.read_text(path).splitlines())
    except OSError:
        return 1
    if n == 0:
        return 1
    return min(max(line, 1), n)


def _parse_row(target: ScanTarget, partition: str, row: dict[str, Any]) -> Candidate | None:
    path = _valid_path(target, str(row.get("file", "")))
    if path is None:
        return None
    severity = str(row.get("severity", "")).lower()
    confidence = str(row.get("confidence", "")).lower()
    cwe = str(row.get("cwe", "")).strip()
    try:
        line = int(row.get("line", 1))
    except (TypeError, ValueError):
        line = 1
    return Candidate(
        path=path,
        line=_clamp_line(target, path, line),
        title=str(row.get("title", "")).strip()[:160] or "security finding",
        vuln_class=str(row.get("vuln_class", "")).strip().lower() or "unknown",
        cwe=cwe,
        rationale=str(row.get("rationale", "")).strip()[:600],
        impact=str(row.get("impact", "")).strip()[:400],
        severity=severity if severity in _SEVERITIES else "medium",
        confidence=confidence if confidence in _CONFIDENCES else "low",
        partition=partition,
    )


def discover_partition(
    target: ScanTarget,
    partition: Partition,
    threat_model: ThreatModel,
    llm: LLMClient,
    cfg: PipelineConfig,
) -> list[Candidate]:
    """Run one discovery pass over a partition; returns parsed candidates (never raises)."""
    code = render_partition(
        target,
        partition.files,
        max_chars_per_file=cfg.max_chars_per_file,
        max_chars_per_prompt=cfg.max_chars_per_prompt,
    )
    if not code:
        return []
    user = prompts.discovery_user(threat_model.as_context(), partition.name, code)
    try:
        data = llm.chat_json(
            messages=[
                {"role": "system", "content": prompts.DISCOVERY_SYSTEM},
                {"role": "user", "content": user},
            ],
            max_tokens=cfg.discovery_max_tokens,
        )
    except Exception:  # noqa: BLE001 - one partition failing must not kill the scan
        return []

    rows = data.get("findings") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        return []
    out: list[Candidate] = []
    for row in rows:
        if isinstance(row, dict):
            cand = _parse_row(target, partition.name, row)
            if cand is not None:
                out.append(cand)
    return out


def _surfaces(target: ScanTarget, cfg: PipelineConfig) -> list[str | None]:
    """Decide the fan-out: focus areas, or [None] for a single whole-repo session."""
    if len(target.files) <= cfg.agent_fanout_min_files:
        return [None]
    components = sorted(
        {sf.path.split("/", 1)[0] if "/" in sf.path else "." for sf in target.files}
    )
    if len(components) <= 1:
        return [None]
    surfaces: list[str | None] = [c for c in components[: cfg.agent_max_surfaces]]
    # Fan-out surfaces come from .py/.js components, so template/config-only dirs get no
    # session. Add a dedicated surface so non-Python attack surface is always audited.
    surfaces.append(
        "ALL templates and config/infra files repo-wide (*.html/*.jinja "
        "templates, settings.py, *.env, *.cfg/*.ini, *.conf, nginx, Dockerfile, "
        "docker-compose, *_seed*) — XSS sinks, secrets, misconfig, debug"
    )
    return surfaces


def _rows_to_candidates(target: ScanTarget, label: str, data: object) -> list[Candidate]:
    rows = data.get("findings") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        return []
    out: list[Candidate] = []
    for row in rows:
        if isinstance(row, dict):
            cand = _parse_row(target, label, row)
            if cand is not None:
                out.append(cand)
    return out


def discover_agentic(
    target: ScanTarget, threat_model: ThreatModel, cfg: PipelineConfig
) -> list[Candidate]:
    """Agentic discovery: fan out one focused kolega-code session per attack surface.

    Large multi-package repos are split by top-level component so each session digs deep
    into one area (a single whole-repo session under-enumerates them). Small repos get one
    session. Results are merged and de-duplicated by (path, line, vuln_class).
    """
    from concurrent.futures import ThreadPoolExecutor

    from kolega_security_scanner.scanners.claude_adaptation import kolega_code

    surfaces = _surfaces(target, cfg)
    tm_ctx = threat_model.as_context()

    def _run(focus: str | None) -> list[Candidate]:
        """One surface, iterated until net-new findings plateau (article's loop)."""
        found: list[Candidate] = []
        seen: set[tuple[str, int, str]] = set()
        for _round in range(max(1, cfg.discovery_rounds)):
            block = "\n".join(f"- {c.path}:{c.line} {c.vuln_class}" for c in found)
            data = kolega_code.run_json(
                prompts.agent_discovery(tm_ctx, focus, already_found=block),
                target.repo_root,
                provider=cfg.agent_provider,
                model=cfg.agent_model,
            )
            new = 0
            for c in _rows_to_candidates(target, focus or "agentic", data):
                key = (c.path, c.line, c.vuln_class)
                if key not in seen:
                    seen.add(key)
                    found.append(c)
                    new += 1
            if new == 0:  # plateau: this round added nothing distinct
                break
        return found

    if len(surfaces) == 1:
        merged = _run(surfaces[0])
    else:
        merged = []
        workers = max(1, min(cfg.agent_surface_concurrency, len(surfaces)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for chunk in pool.map(_run, surfaces):
                merged.extend(chunk)

    # De-duplicate across surfaces: same sink (path, line, class) reported twice.
    seen: set[tuple[str, int, str]] = set()
    unique: list[Candidate] = []
    for c in merged:
        key = (c.path, c.line, c.vuln_class)
        if key not in seen:
            seen.add(key)
            unique.append(c)
    return unique


def discover_variants(
    target: ScanTarget,
    confirmed: list[Candidate],
    threat_model: ThreatModel,
    cfg: PipelineConfig,
) -> list[Candidate]:
    """Phase 6 variant analysis: find MORE instances of already-confirmed bug patterns."""
    if not confirmed:
        return []
    from kolega_security_scanner.scanners.claude_adaptation import kolega_code

    block = "\n".join(
        f"- {c.vuln_class} ({c.cwe}) at {c.path}:{c.line} — {c.title}" for c in confirmed
    )
    data = kolega_code.run_json(
        prompts.agent_variants(threat_model.as_context(), block),
        target.repo_root,
        provider=cfg.agent_provider,
        model=cfg.agent_model,
    )
    cands = _rows_to_candidates(target, "variant", data)
    # Drop any that duplicate a confirmed finding (same sink).
    confirmed_keys = {(c.path, c.line, c.vuln_class) for c in confirmed}
    return [c for c in cands if (c.path, c.line, c.vuln_class) not in confirmed_keys]


__all__ = ["discover_partition", "discover_agentic", "discover_variants"]
