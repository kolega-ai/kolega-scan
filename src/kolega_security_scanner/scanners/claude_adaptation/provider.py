"""The Kolega Scan OSS scan providers (``kolega-scan-oss-v1``/``-v2``/``-ref``).

An LLM-driven adaptation of Anthropic's "Using LLMs to secure source code" find-and-fix
loop (https://claude.com/blog/using-llms-to-secure-source-code), implemented as a
``ScanProvider`` over this harness's ``LLMClient``:

  Phase 1  Threat model   build_threat_model()  — code-driven; human interview omitted
  Phase 2  Sandboxing     N/A in a findings-only CLI -> verification is code-analysis only
  Phase 3  Discovery      partition by attack surface -> one structured pass per partition
  Phase 4  Verification   independent adversarial verifier per candidate (majority vote)
  Phase 5  Triage         deterministic dedupe + severity ranking
  Phase 6  Patching       out of scope for a scanner; left to downstream tooling

The pipeline is LLM-driven, so it REQUIRES a client: the provider builds its own
client(s) from the environment inside ``scan()`` and raises a clear ``LLMConfigError``
when no API key is configured (the CLI maps that to a usage error, exit 2).
"""

from __future__ import annotations

import logging
import time

import kolega_security_scanner.llm.client as _llm_mod
from kolega_security_scanner.llm.client import LLMClient
from kolega_security_scanner.scanner.config import ScanConfig
from kolega_security_scanner.scanner.enumerate import enumerate_sources
from kolega_security_scanner.scanner.models import ScanResult
from kolega_security_scanner.scanners.claude_adaptation.config import (
    DEEPSEEK_MATRIX_MODELS,
    DEEPSEEK_VARIANT_NAME,
    KIMI_ENSEMBLE_MODELS,
    KIMI_ENSEMBLE_VARIANT_NAME,
    PROVIDER_NAME,
    PipelineConfig,
)
from kolega_security_scanner.scanners.claude_adaptation.discovery import (
    discover_agentic,
    discover_partition,
    discover_variants,
)
from kolega_security_scanner.scanners.claude_adaptation.findings import to_finding
from kolega_security_scanner.scanners.claude_adaptation.partition import partition_files
from kolega_security_scanner.scanners.claude_adaptation.threat_model import build_threat_model
from kolega_security_scanner.scanners.claude_adaptation.triage import triage
from kolega_security_scanner.scanners.claude_adaptation.verification import (
    verify_batch_agentic,
    verify_candidate,
)

log = logging.getLogger(__name__)


def _log(message: str) -> None:
    """Emit a progress milestone (INFO). Routed to the package logger, not stdout."""
    log.info(message)


def _dump(repo_dir: str, name: str, rows: object) -> None:
    """Phase-attribution capture: write a phase artifact under $KA_DUMP_DIR/<repo>/.

    No-op unless KA_DUMP_DIR is set, so production scans are unaffected. Used to trace
    which phase (discovery / verification / triage) loses each ground-truth vuln.
    """
    import json
    import os
    from pathlib import Path

    base = os.environ.get("KA_DUMP_DIR")
    if not base:
        return
    out = Path(base) / repo_dir
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{name}.json").write_text(json.dumps(rows, indent=2, default=lambda o: o.__dict__))


class ClaudeAdaptationScanProvider:
    """Default scanner: the six-phase LLM find-and-fix loop (discovery -> verify -> triage)."""

    name = PROVIDER_NAME

    def __init__(self, cfg: PipelineConfig | None = None, name: str = PROVIDER_NAME) -> None:
        """Hold the pipeline tuning config and the registered ``--scanner`` name."""
        self._cfg = cfg or PipelineConfig()
        self.name = name

    def _resolve_llm(self, config: ScanConfig) -> LLMClient:
        """Build the base client from the environment (raises if no key configured)."""
        return _llm_mod.build_llm_client(config.llm_api_key_env)

    def _stage_clients(
        self, models: tuple[str, ...], config: ScanConfig, base: LLMClient
    ) -> list[LLMClient]:
        """One client per model for a matrix stage; fall back to the base client."""
        if not models:
            return [base]
        return [_llm_mod.build_llm_client_for_model(m, config.llm_api_key_env) for m in models]

    def scan(self, config: ScanConfig) -> ScanResult:
        """Run the full pipeline over the repo and return ranked, verified findings."""
        cfg = self._cfg
        # Agentic phases drive kolega-code, not the LiteLLM chat client, so don't
        # require a chat-client key in that mode; otherwise build one from env.
        client = None if cfg.agentic else self._resolve_llm(config)
        # LLM-only pipeline runs no regex over source, so keep dense single-file apps
        # (long lines) that the regex-ReDoS minified-skip would otherwise drop.
        started = time.monotonic()
        target = enumerate_sources(config.repo_path, skip_minified=False)
        repo_dir = config.repo_path.name

        if not target.files:
            _log("no source files enumerated; nothing to scan")
            return ScanResult(repo_dir=repo_dir, findings=[])
        _log(f"scanning {repo_dir}: {len(target.files)} source files")

        # Phase 1 — threat model (context for every later phase).
        _log("phase 1/4: building threat model…")
        threat_model = build_threat_model(target, client, cfg)
        _log(f"threat model: {threat_model.status}")

        # Phase 3 — discovery. Agentic: one repo-navigating session. Else: per-partition.
        candidates = []
        if cfg.agentic:
            candidates = discover_agentic(target, threat_model, cfg)[: cfg.max_candidates]
        else:
            assert client is not None  # non-agentic mode always resolves a client
            disc_clients = self._stage_clients(cfg.discovery_models, config, client)
            if len(disc_clients) > 1:
                _log(f"matrix discovery across {len(cfg.discovery_models)} models")
            partitions = partition_files(target, max_files=cfg.max_files_per_partition)
            _log(f"phase 2/4: discovery over {len(partitions)} partitions…")
            seen: set[tuple[str, int, str]] = set()
            for i, part in enumerate(partitions, start=1):
                for dc in disc_clients:
                    for cand in discover_partition(target, part, threat_model, dc, cfg):
                        key = (cand.path, cand.line, cand.vuln_class)
                        if key in seen:
                            continue
                        seen.add(key)
                        candidates.append(cand)
                log.debug(
                    "  discovery: partition %d/%d — %d candidates so far",
                    i,
                    len(partitions),
                    len(candidates),
                )
                if len(candidates) >= cfg.max_candidates:
                    _log(f"candidate cap {cfg.max_candidates} reached; stopping discovery")
                    candidates = candidates[: cfg.max_candidates]
                    break
        _log(f"discovery candidates: {len(candidates)}")
        _dump(repo_dir, "01_threat_model", threat_model)
        _dump(repo_dir, "02_discovery", candidates)
        _log(f"phase 3/4: verifying {len(candidates)} candidates…")

        # Phase 4 — independent adversarial verification (drop unconfirmed). Agentic mode
        # batches by file (one session per file) instead of one session per candidate.
        if cfg.agentic:
            ruled = verify_batch_agentic(target, candidates, threat_model, cfg)
            _dump(repo_dir, "03_verification", ruled)
            verified = [vc for vc in ruled if vc.verdict.exploitable]
        else:
            assert client is not None  # non-agentic mode always resolves a client
            verify_clients = self._stage_clients(cfg.verify_models, config, client)
            if len(verify_clients) > 1:
                _log(f"matrix verify across {len(cfg.verify_models)} models ({cfg.combine})")
            verified = []
            for j, cand in enumerate(candidates, start=1):
                vcs = [
                    verify_candidate(target, cand, threat_model, vclient, cfg)
                    for vclient in verify_clients
                ]
                yes = [v for v in vcs if v.verdict.exploitable]
                # union: any model confirms (recall). consensus: majority confirm (precision).
                confirmed = (len(yes) * 2 > len(vcs)) if cfg.combine == "consensus" else bool(yes)
                if confirmed:
                    verified.append(yes[0] if yes else vcs[0])
                log.debug(
                    "  verify: %d/%d — %d confirmed so far", j, len(candidates), len(verified)
                )
        _log(f"verified findings: {len(verified)}/{len(candidates)}")

        # Phase 6 (recall) — variant analysis: seed a pass with the confirmed findings to
        # find MORE instances of the same patterns elsewhere, then verify those too.
        if cfg.agentic and verified:
            variants = discover_variants(
                target, [vc.candidate for vc in verified], threat_model, cfg
            )
            if variants:
                vruled = verify_batch_agentic(target, variants, threat_model, cfg)
                confirmed_variants = [vc for vc in vruled if vc.verdict.exploitable]
                verified.extend(confirmed_variants)
                _dump(repo_dir, "04_variants", vruled)
                _log(f"variant analysis: +{len(confirmed_variants)} (from {len(variants)})")

        # Phase 5 — dedupe + rank, then convert to wire-format findings.
        _log("phase 4/4: triage (dedupe + rank)…")
        ranked = triage(verified)
        _dump(repo_dir, "05_final", ranked)
        findings = [to_finding(vc) for vc in ranked]
        _log(f"done — {len(findings)} findings in {int(time.monotonic() - started)}s")

        return ScanResult(repo_dir=repo_dir, findings=findings)


def build_provider() -> ClaudeAdaptationScanProvider:
    """Factory for the base default scanner (single-model)."""
    return ClaudeAdaptationScanProvider()


def build_deepseek_matrix_provider() -> ClaudeAdaptationScanProvider:
    """Matrix variant: DeepSeek flash+pro across discovery + verify (union for recall)."""
    cfg = PipelineConfig(
        discovery_models=DEEPSEEK_MATRIX_MODELS,
        verify_models=DEEPSEEK_MATRIX_MODELS,
        combine="union",
    )
    return ClaudeAdaptationScanProvider(cfg, name=DEEPSEEK_VARIANT_NAME)


def build_kimi_ensemble_provider() -> ClaudeAdaptationScanProvider:
    """Ensemble variant: DeepSeek flash+pro + Kimi across discovery + verify (union)."""
    cfg = PipelineConfig(
        discovery_models=KIMI_ENSEMBLE_MODELS,
        verify_models=KIMI_ENSEMBLE_MODELS,
        combine="union",
    )
    return ClaudeAdaptationScanProvider(cfg, name=KIMI_ENSEMBLE_VARIANT_NAME)


__all__ = [
    "ClaudeAdaptationScanProvider",
    "build_provider",
    "build_deepseek_matrix_provider",
    "build_kimi_ensemble_provider",
]
