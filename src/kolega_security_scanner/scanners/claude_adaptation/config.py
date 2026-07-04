"""Tunable knobs for the claude-adaptation pipeline (no magic numbers in the stages)."""

from __future__ import annotations

from dataclasses import dataclass

# The single-model reference pipeline (kept registered for development; not the default).
PROVIDER_NAME = "kolega-scan-oss-ref"
# Shipped product versions: run discovery + verification across several models and
# combine the results. ``kolega-scan-oss-v1`` (the default) uses the DeepSeek
# flash+pro pair; ``kolega-scan-oss-v2`` adds Kimi to the ensemble.
DEEPSEEK_VARIANT_NAME = "kolega-scan-oss-v1"
KIMI_ENSEMBLE_VARIANT_NAME = "kolega-scan-oss-v2"
# Model sets used by each variant (``provider/model`` specs; resolved by the LLM client).
DEEPSEEK_MATRIX_MODELS = ("deepseek/deepseek-v4-flash", "deepseek/deepseek-v4-pro")
KIMI_ENSEMBLE_MODELS = (
    "deepseek/deepseek-v4-flash",
    "deepseek/deepseek-v4-pro",
    "moonshot/kimi-k2.6",
)


@dataclass(frozen=True)
class PipelineConfig:
    """Pipeline budgets and fan-out controls.

    Defaults are tuned for the deepseek-v4-flash default model: cheap enough to run
    per-partition discovery and per-candidate verification without excessive cost.
    """

    # Phase 3a partitioning: how many files one discovery prompt may carry, and the
    # per-file / per-prompt character budgets that bound token usage.
    max_files_per_partition: int = 12
    max_chars_per_file: int = 4_000
    max_chars_per_prompt: int = 28_000

    # Phase 3 discovery: per-prompt candidate cap and overall cap (recall vs cost).
    discovery_max_tokens: int = 8_000
    max_candidates: int = 200

    # Phase 4 verification: independent verifier count (majority vote when > 1).
    verifiers: int = 1
    verify_max_tokens: int = 1_500
    # Lines of code context handed to the verifier around the finding.
    verify_context_lines: int = 40

    # Phase 1 threat model.
    threat_model_max_tokens: int = 4_000
    threat_model_max_files: int = 60

    # Agentic backend (kolega-code ask): when True, phases 1/3/4 hand the task to a
    # repo-navigating agent session instead of a single pre-stuffed chat_json call.
    # Lifts recall (no truncation, cross-file flow following) at higher latency/cost.
    agentic: bool = False
    agent_provider: str = "deepseek"
    agent_model: str = "deepseek-v4-pro"
    # Agentic discovery fan-out: repos with more than agent_fanout_min_files source files
    # are split into per-component surfaces (one focused agent session each, capped at
    # agent_max_surfaces, run agent_surface_concurrency at a time). Smaller repos get a
    # single whole-repo session. Fan-out is the recall fix for large multi-package apps.
    agent_fanout_min_files: int = 8
    agent_max_surfaces: int = 10
    agent_surface_concurrency: int = 4
    # Iterate-until-plateau discovery (article: run discovery repeatedly until net-new
    # findings dry up). Per surface, run up to discovery_rounds rounds, each asking for
    # vulns NOT already found; stop early when a round adds nothing new.
    discovery_rounds: int = 3

    # Matrix mode (non-agentic path): when non-empty, discovery and verification run
    # once per model in these sets and the results are combined. Empty -> single-model
    # behavior using the injected/default client (the base scanner, unchanged).
    discovery_models: tuple[str, ...] = ()
    verify_models: tuple[str, ...] = ()
    # How to combine multi-model verification verdicts: "union" (exploitable if ANY model
    # confirms -> recall) or "consensus" (exploitable if a MAJORITY confirm -> precision).
    combine: str = "union"


__all__ = [
    "PROVIDER_NAME",
    "DEEPSEEK_VARIANT_NAME",
    "KIMI_ENSEMBLE_VARIANT_NAME",
    "DEEPSEEK_MATRIX_MODELS",
    "KIMI_ENSEMBLE_MODELS",
    "PipelineConfig",
]
