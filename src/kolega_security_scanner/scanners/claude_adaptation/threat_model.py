"""Phase 1 — code-driven threat modeling.

Faithful to the article's first phase: feed entry points and structure to the model and
ask for a threat model (assets, entry points, trust boundaries, trusted inputs, relevant
vuln classes). The human-interview step is intentionally omitted — the CLI is not
interactive. The result is injected as context into discovery, verification, and triage,
which is the article's main false-positive lever ("threat model grounding").
"""

from __future__ import annotations

from kolega_security_scanner.llm.client import LLMClient
from kolega_security_scanner.scanner.models import ScanTarget
from kolega_security_scanner.scanners.claude_adaptation import prompts
from kolega_security_scanner.scanners.claude_adaptation.coderender import render_file_block
from kolega_security_scanner.scanners.claude_adaptation.config import PipelineConfig
from kolega_security_scanner.scanners.claude_adaptation.models import ThreatModel
from kolega_security_scanner.scanners.claude_adaptation.partition import select_entry_points


def _str_tuple(value: object) -> tuple[str, ...]:
    """Coerce an LLM JSON value into a tuple of clean strings (defensive)."""
    if not isinstance(value, list):
        return ()
    return tuple(str(v).strip() for v in value if str(v).strip())


def build_threat_model(
    target: ScanTarget, llm: LLMClient | None, cfg: PipelineConfig
) -> ThreatModel:
    """Run the Phase 1 threat-model pass; never raises (degrades to status on failure).

    ``llm`` may be ``None`` only in agentic mode, which drives kolega-code instead of
    the chat client.
    """
    if cfg.agentic:
        from kolega_security_scanner.scanners.claude_adaptation import kolega_code

        data = kolega_code.run_json(
            prompts.agent_threat_model(),
            target.repo_root,
            provider=cfg.agent_provider,
            model=cfg.agent_model,
        )
        return _from_json(data) if data is not None else ThreatModel(status="error:agent")

    assert llm is not None, "non-agentic threat model requires an LLM client"
    entry_files = select_entry_points(target, max_files=cfg.threat_model_max_files)
    file_tree = "\n".join(sf.path for sf in target.files[:400])
    entry_source = "\n\n".join(
        block
        for rel in entry_files[:12]
        if (block := render_file_block(target, rel, max_chars=cfg.max_chars_per_file))
    )

    user = prompts.threat_model_user(file_tree, entry_source)
    try:
        data = llm.chat_json(
            messages=[
                {"role": "system", "content": prompts.THREAT_MODEL_SYSTEM},
                {"role": "user", "content": user},
            ],
            max_tokens=cfg.threat_model_max_tokens,
        )
    except Exception as exc:  # noqa: BLE001 - never fatal; downstream degrades gracefully
        return ThreatModel(status=f"error:{type(exc).__name__}")
    return _from_json(data)


def _from_json(data: object) -> ThreatModel:
    """Build a ThreatModel from parsed JSON (shared by chat + agentic paths)."""
    if not isinstance(data, dict):
        return ThreatModel(status="error:no_json")
    return ThreatModel(
        summary=str(data.get("summary", "")).strip(),
        assets=_str_tuple(data.get("assets")),
        entry_points=_str_tuple(data.get("entry_points")),
        trust_boundaries=_str_tuple(data.get("trust_boundaries")),
        trusted_inputs=_str_tuple(data.get("trusted_inputs")),
        vuln_classes=_str_tuple(data.get("vuln_classes")),
        status="ok",
    )


__all__ = ["build_threat_model"]
