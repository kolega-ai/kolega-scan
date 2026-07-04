"""Phase 4 — verification: independent, adversarial re-examination of each candidate.

Faithful to the article: the verifier gets ONLY the finding description and the code (no
discovery reasoning, no shared state), and is told to assume a false positive and try to
disprove it. With ``cfg.verifiers > 1`` we run independent verifiers and take a majority
vote. Without a sandbox we cannot run PoCs, so verification is code-analysis only — the
article explicitly permits this at lower precision.
"""

from __future__ import annotations

from pathlib import Path

from kolega_security_scanner.llm.client import LLMClient
from kolega_security_scanner.scanner.models import ScanTarget
from kolega_security_scanner.scanners.claude_adaptation import prompts
from kolega_security_scanner.scanners.claude_adaptation.coderender import context_window
from kolega_security_scanner.scanners.claude_adaptation.config import PipelineConfig
from kolega_security_scanner.scanners.claude_adaptation.models import (
    Candidate,
    ThreatModel,
    Verdict,
    VerifiedCandidate,
)

_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def _finding_desc(c: Candidate) -> str:
    """Render a candidate as the neutral finding description handed to the verifier."""
    return (
        f"Title: {c.title}\nClass: {c.vuln_class} ({c.cwe})\n"
        f"Location: {c.path}:{c.line}\nClaim: {c.rationale}\nImpact: {c.impact}"
    )


def _one_vote(
    candidate: Candidate,
    threat_model: ThreatModel,
    code: str,
    llm: LLMClient,
    cfg: PipelineConfig,
) -> Verdict:
    user = prompts.verify_user(threat_model.as_context(), _finding_desc(candidate), code)
    try:
        data = llm.chat_json(
            messages=[
                {"role": "system", "content": prompts.VERIFY_SYSTEM},
                {"role": "user", "content": user},
            ],
            max_tokens=cfg.verify_max_tokens,
        )
    except Exception as exc:  # noqa: BLE001 - a verifier failure abstains (not exploitable)
        return Verdict(exploitable=False, reason=f"verifier error: {type(exc).__name__}")
    if not isinstance(data, dict):
        return Verdict(exploitable=False, reason="verifier returned no JSON")
    sev = str(data.get("severity", "")).lower()
    return Verdict(
        exploitable=bool(data.get("exploitable")),
        reason=str(data.get("reason", "")).strip()[:400],
        severity=sev if sev in _SEVERITIES else None,
    )


def _agent_vote(
    target: ScanTarget, candidate: Candidate, threat_model: ThreatModel, cfg: PipelineConfig
) -> Verdict:
    """One agentic verifier: kolega-code navigates the repo for controls, then rules."""
    from kolega_security_scanner.scanners.claude_adaptation import kolega_code

    data = kolega_code.run_json(
        prompts.agent_verify(threat_model.as_context(), _finding_desc(candidate)),
        target.repo_root,
        model=cfg.agent_model,
    )
    if not isinstance(data, dict):
        return Verdict(exploitable=False, reason="agent verifier returned no JSON")
    sev = str(data.get("severity", "")).lower()
    return Verdict(
        exploitable=bool(data.get("exploitable")),
        reason=str(data.get("reason", "")).strip()[:400],
        severity=sev if sev in _SEVERITIES else None,
    )


def verify_candidate(
    target: ScanTarget,
    candidate: Candidate,
    threat_model: ThreatModel,
    llm: LLMClient,
    cfg: PipelineConfig,
) -> VerifiedCandidate:
    """Run ``cfg.verifiers`` independent verifiers; confirm on a strict majority vote."""
    if cfg.agentic:
        vote = _agent_vote(target, candidate, threat_model, cfg)
        return VerifiedCandidate(candidate=candidate, verdict=vote, votes=(vote,))

    try:
        text = target.read_text(candidate.path)
    except OSError:
        text = ""
    code = context_window(text, candidate.line, radius=cfg.verify_context_lines)

    votes = tuple(
        _one_vote(candidate, threat_model, code, llm, cfg) for _ in range(max(1, cfg.verifiers))
    )
    yes = [v for v in votes if v.exploitable]
    exploitable = len(yes) * 2 > len(votes)  # strict majority
    # On confirmation, keep the first confirming vote's reason/recalibrated severity;
    # otherwise surface the first (rejecting) vote's reason.
    chosen = yes[0] if yes else votes[0]
    final = Verdict(exploitable=exploitable, reason=chosen.reason, severity=chosen.severity)
    return VerifiedCandidate(candidate=candidate, verdict=final, votes=votes)


def _verify_file_group_once(
    block: str, tm_ctx: str, repo_root: Path, cfg: PipelineConfig
) -> dict[int, Verdict]:
    """One independent batched verifier session; returns idx -> Verdict."""
    from kolega_security_scanner.scanners.claude_adaptation import kolega_code

    data = kolega_code.run_json(
        prompts.agent_verify_batch(tm_ctx, block),
        repo_root,
        provider=cfg.agent_provider,
        model=cfg.agent_model,
    )
    verdicts: dict[int, Verdict] = {}
    rows = data.get("verdicts") if isinstance(data, dict) else None
    if isinstance(rows, list):
        for r in rows:
            if not isinstance(r, dict) or not isinstance(r.get("idx"), int):
                continue
            sev = str(r.get("severity", "")).lower()
            verdicts[r["idx"]] = Verdict(
                exploitable=bool(r.get("exploitable")),
                reason=str(r.get("reason", "")).strip()[:400],
                severity=sev if sev in _SEVERITIES else None,
            )
    return verdicts


def _verify_file_group(
    candidates: list[Candidate], threat_model: ThreatModel, repo_root: Path, cfg: PipelineConfig
) -> list[VerifiedCandidate]:
    """Verify every candidate in one file via N independent verifiers + majority vote.

    Article Phase 4: run multiple independent verifiers and confirm on a majority. This
    recovers true positives that a single strict verifier wrongly rejects, while keeping
    the FP suppression of the strict prompt.
    """
    block = "\n".join(
        f"[{i}] {_finding_desc(c)}".replace("\n", " | ") for i, c in enumerate(candidates)
    )
    tm_ctx = threat_model.as_context()
    n = max(1, cfg.verifiers)
    rounds = [_verify_file_group_once(block, tm_ctx, repo_root, cfg) for _ in range(n)]

    out: list[VerifiedCandidate] = []
    for i, c in enumerate(candidates):
        votes = tuple(r[i] for r in rounds if i in r)
        if not votes:
            v = Verdict(exploitable=False, reason="no verdict returned for finding")
            out.append(VerifiedCandidate(candidate=c, verdict=v, votes=(v,)))
            continue
        yes = [v for v in votes if v.exploitable]
        exploitable = len(yes) * 2 > n  # strict majority of the N verifiers
        chosen = yes[0] if (exploitable and yes) else votes[0]
        final = Verdict(exploitable=exploitable, reason=chosen.reason, severity=chosen.severity)
        out.append(VerifiedCandidate(candidate=c, verdict=final, votes=votes))
    return out


def verify_batch_agentic(
    target: ScanTarget,
    candidates: list[Candidate],
    threat_model: ThreatModel,
    cfg: PipelineConfig,
) -> list[VerifiedCandidate]:
    """Batch agentic verification: group candidates by file, one session per file.

    Collapses the per-candidate agent sessions (the wall-clock killer) into one session
    per file — the agent reads that file and its compensating controls once and rules on
    every finding in it. File groups run concurrently (bounded by agent_surface_concurrency).
    """
    from concurrent.futures import ThreadPoolExecutor

    groups: dict[str, list[Candidate]] = {}
    for c in candidates:
        groups.setdefault(c.path, []).append(c)

    def _run(group: list[Candidate]) -> list[VerifiedCandidate]:
        return _verify_file_group(group, threat_model, target.repo_root, cfg)

    out: list[VerifiedCandidate] = []
    group_lists = list(groups.values())
    workers = max(1, min(cfg.agent_surface_concurrency, len(group_lists) or 1))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for chunk in pool.map(_run, group_lists):
            out.extend(chunk)
    return out


__all__ = ["verify_candidate", "verify_batch_agentic"]
